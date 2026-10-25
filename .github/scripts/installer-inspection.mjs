// Inspects the packaged application inside an uploaded NSIS installer before a release can be verified or published.
// A build made with the source repository's --updater-test-fixture option trusts a loopback feed and a throwaway key
// but has the same installer name and app id as a real build, so the name, latest.yml and the signed statement cannot
// tell them apart. This opens the installer itself: NSIS payload -> $PLUGINSDIR/app-64.7z -> resources/app.asar,
// checks the packaged identity against release-config.json and the release version, and rejects the test fixture.
// Uses only node and the 7z command (7-Zip, preinstalled on the ubuntu-24.04 runner). Anything that cannot be
// inspected fails closed.
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fail, ReleaseError } from './lib.mjs';

export const FIXTURE_FILE = 'update-test-fixture.json';
export const CHANNEL_FILE = 'build-channel.json';
export const APP_PAYLOAD = '$PLUGINSDIR/app-64.7z';
const PAYLOAD_NAME = /^\$PLUGINSDIR\/app-[^/]*\.7z$/i;
const MAX_ASAR_HEADER = 16 * 1024 * 1024;
const MAX_IDENTITY_FILE = 64 * 1024;
const SEMVER = /^\d+\.\d+\.\d+$/;

const isFixturePath = p => p.split(/[\\/]/).pop().toLowerCase() === FIXTURE_FILE;

// electron-builder names the package (and so the per-user install folder) after the installer prefix, lower-cased.
export function expectedPackageName(config) {
  const m = /^([A-Za-z0-9-]+)-Setup-\{version\}\.exe$/.exec(config.installerTemplate);
  if (!m) fail('inspect-config', `installerTemplate ${JSON.stringify(config.installerTemplate)} is not <Package>-Setup-{version}.exe`);
  return m[1].toLowerCase();
}

function run7z(tool, argv) {
  const r = spawnSync(tool, argv, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 15 * 60 * 1000, stdio: ['ignore', 'pipe', 'pipe'] });
  if (r.error && r.error.code === 'ENOENT') fail('inspect-tool-missing', `installer inspection needs the ${tool} command (7-Zip), which is not available; refusing to continue`);
  if (r.error) fail('inspect-tool-failed', `${tool} could not run: ${r.error.code || r.error.message}`);
  if (r.status !== 0) fail('installer-unreadable', `${tool} ${argv[0]} failed (exit ${r.status}): ${String(r.stderr || r.stdout).trim().split('\n').slice(-3).join(' ').slice(0, 300)}`);
  return r.stdout;
}

// Parses `7z l -slt` output: the archive's own properties, then one block per entry.
export function parseSltListing(text) {
  const sep = text.indexOf('\n----------\n');
  if (sep < 0) fail('installer-malformed', 'archive listing has no entry section');
  const props = block => Object.fromEntries(block.split('\n').map(l => /^([^=]+?) = (.*)$/.exec(l)).filter(Boolean).map(m => [m[1], m[2]]));
  const head = '\n' + text.slice(0, sep), archiveStart = head.lastIndexOf('\n--\n');
  if (archiveStart < 0) fail('installer-malformed', 'archive listing has no archive section');
  const archive = props(head.slice(archiveStart + 4));
  const entries = text.slice(sep + 12).split(/\n\s*\n/).map(props).filter(e => 'Path' in e)
    .map(e => ({ path: e.Path.replaceAll('\\', '/'), dir: e.Folder === '+' || /D/.test(e.Attributes || ''), size: e.Size === '' || e.Size === undefined ? null : Number(e.Size) }));
  return { type: archive.Type, entries };
}

function list(tool, file) {
  return parseSltListing(run7z(tool, ['l', '-slt', '-sccUTF-8', '--', file]).replaceAll('\r\n', '\n'));
}

function readExactly(fd, length, position) {
  const buf = Buffer.alloc(length);
  let done = 0;
  while (done < length) {
    const n = fs.readSync(fd, buf, done, length - done, position + done);
    if (n === 0) fail('asar-malformed', 'app.asar ends early');
    done += n;
  }
  return buf;
}

// Electron ASAR: pickled uint32 header size, pickled JSON file tree, then file data. Every bound is checked.
export function readAsar(file) {
  let fd;
  try { fd = fs.openSync(file, 'r'); } catch (e) { fail('asar-unreadable', `cannot read app.asar: ${e.code}`); }
  try {
    const size = fs.fstatSync(fd).size;
    if (size < 16) fail('asar-malformed', 'app.asar is too small to be an archive');
    const pre = readExactly(fd, 16, 0);
    const headerSize = pre.readUInt32LE(4), payload = pre.readUInt32LE(8), strLen = pre.readInt32LE(12);
    if (pre.readUInt32LE(0) !== 4 || headerSize > MAX_ASAR_HEADER || headerSize + 8 > size || payload !== headerSize - 4 || strLen < 2 || strLen > payload - 4) fail('asar-malformed', 'app.asar header is malformed');
    let header;
    try { header = JSON.parse(readExactly(fd, strLen, 16).toString('utf8')); } catch (e) { if (e instanceof ReleaseError) throw e; fail('asar-malformed', 'app.asar header is not valid JSON'); }
    const base = 8 + headerSize, entries = new Map();
    (function walk(node, prefix) {
      if (!node || typeof node !== 'object' || !node.files || typeof node.files !== 'object' || Array.isArray(node.files)) fail('asar-malformed', `app.asar directory entry is malformed${prefix ? ' at ' + prefix : ''}`);
      for (const [name, entry] of Object.entries(node.files)) {
        if (!name || name === '.' || name === '..' || /[\\/\0]/.test(name)) fail('asar-malformed', 'app.asar has an invalid entry name');
        const p = prefix ? `${prefix}/${name}` : name;
        if (!entry || typeof entry !== 'object') fail('asar-malformed', `app.asar entry ${p} is malformed`);
        if ('files' in entry) { entries.set(p, { type: 'dir' }); walk(entry, p); continue; }
        if ('link' in entry) { entries.set(p, { type: 'link' }); continue; }
        if (!Number.isSafeInteger(entry.size) || entry.size < 0) fail('asar-malformed', `app.asar entry ${p} has no valid size`);
        if (entry.unpacked === true) { entries.set(p, { type: 'file', unpacked: true, size: entry.size, integrity: entry.integrity }); continue; }
        const offset = Number(entry.offset);
        if (typeof entry.offset !== 'string' || !/^\d+$/.test(entry.offset) || !Number.isSafeInteger(offset) || base + offset + entry.size > size) fail('asar-malformed', `app.asar entry ${p} points outside the archive`);
        entries.set(p, { type: 'file', unpacked: false, size: entry.size, offset: base + offset, integrity: entry.integrity });
      }
    })(header, '');
    // Reads one packed file and checks it against the SHA-256 the header records for it.
    const readFile = p => {
      const e = entries.get(p);
      if (!e || e.type !== 'file') fail('identity-missing', `${p} is missing from app.asar`);
      if (e.unpacked) fail('identity-malformed', `${p} is stored outside app.asar`);
      if (e.size > MAX_IDENTITY_FILE) fail('identity-malformed', `${p} in app.asar is too large`);
      const data = readExactly(fd, e.size, e.offset);
      const integ = e.integrity;
      if (!integ || integ.algorithm !== 'SHA256' || typeof integ.hash !== 'string') fail('identity-malformed', `${p} in app.asar has no SHA-256 integrity record`);
      if (crypto.createHash('sha256').update(data).digest('hex') !== integ.hash.toLowerCase()) fail('identity-malformed', `${p} in app.asar does not match its integrity record`);
      return data;
    };
    return { entries, readFile, close: () => fs.closeSync(fd) };
  } catch (e) { try { fs.closeSync(fd); } catch { /* already closed */ } throw e; }
}

function identityJson(asar, name) {
  let data;
  try { data = JSON.parse(asar.readFile(name).toString('utf8')); } catch (e) { if (e instanceof ReleaseError) throw e; fail('identity-malformed', `${name} in app.asar is not valid JSON`); }
  if (!data || typeof data !== 'object' || Array.isArray(data)) fail('identity-malformed', `${name} in app.asar is not a JSON object`);
  return data;
}

// Checks the packaged app identity and rejects the updater test fixture. Exported for tests.
export function checkAppAsar(file, config, version) {
  const asar = readAsar(file);
  try {
    const fixtures = [...asar.entries.keys()].filter(isFixturePath);
    if (fixtures.length) fail('fixture-build', `the installer is an updater TEST build (app.asar contains ${fixtures[0]}); it must never be released`);
    const pkg = identityJson(asar, 'package.json'), name = expectedPackageName(config);
    if (pkg.name !== name) fail('identity-mismatch', `packaged app name is ${JSON.stringify(pkg.name)}, expected ${name}`);
    if (pkg.version !== version) fail('identity-mismatch', `packaged app version is ${JSON.stringify(pkg.version)}, expected ${version}`);
    const stamp = identityJson(asar, CHANNEL_FILE);
    if (stamp.schemaVersion !== 1 || stamp.channel !== config.channel || stamp.version !== version) fail('identity-mismatch', `packaged ${CHANNEL_FILE} says ${JSON.stringify({ channel: stamp.channel, version: stamp.version })}, expected ${config.channel} ${version}`);
    return { name, channel: stamp.channel, version: stamp.version };
  } finally { asar.close(); }
}

// app-update.yml as electron-builder writes it is flat `key: value` lines. Parsed strictly: any line that is not a
// plain scalar pair, an empty value, or a repeated key (even with the same value) is rejected, so the first match can
// never hide a conflicting second one.
export function parseAppUpdateYml(text) {
  const out = new Map();
  for (const raw of text.replace(/\r\n/g, '\n').split('\n')) {
    if (raw.trim() === '') continue;
    const m = /^([A-Za-z][A-Za-z0-9]*): ?(.*?)\s*$/.exec(raw);
    if (!m) fail('identity-malformed', `app-update.yml has a line that is not a plain "key: value" pair: ${JSON.stringify(raw.slice(0, 60))}`);
    let value = m[2];
    const quoted = /^(["'])(.*)\1$/.exec(value);
    if (quoted) value = quoted[2];
    if (value === '' || /["'#]/.test(value) || /\s/.test(value)) fail('identity-malformed', `app-update.yml ${m[1]} has a missing or malformed value`);
    if (out.has(m[1])) fail('identity-malformed', `app-update.yml repeats the key ${m[1]}`);
    out.set(m[1], value);
  }
  return out;
}

// app-update.yml (written by electron-builder beside app.asar) must name this release repository, each of provider,
// owner and repo exactly once.
export function checkAppUpdateText(text, config) {
  const yml = parseAppUpdateYml(text);
  for (const k of ['provider', 'owner', 'repo']) if (!yml.has(k)) fail('identity-missing', `app-update.yml has no ${k}`);
  if (yml.get('provider') !== 'github' || `${yml.get('owner')}/${yml.get('repo')}` !== config.repo) fail('identity-mismatch', `packaged app-update.yml points at ${yml.get('provider')}:${yml.get('owner')}/${yml.get('repo')}, expected github:${config.repo}`);
}

function checkAppUpdateYml(file, config) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) { fail('identity-missing', `resources/app-update.yml is missing from the installer: ${e.code}`); }
  checkAppUpdateText(text, config);
}

// Inspects one installer file. `expectedSha512` binds the decision to the exact bytes whose hashes were verified.
export function inspectInstaller(installerFile, config, version, { sevenZip = '7z', expectedSha512 = null } = {}) {
  if (!SEMVER.test(String(version))) fail('inspect-usage', 'version must be plain X.Y.Z');
  let data;
  try { data = fs.readFileSync(installerFile); } catch (e) { fail('installer-unreadable', `cannot read the installer: ${e.code}`); }
  if (data.length < 2 || data[0] !== 0x4d || data[1] !== 0x5a) fail('installer-malformed', 'the installer is not a Windows executable');
  const sha512 = crypto.createHash('sha512').update(data).digest('base64');
  if (expectedSha512 !== null && sha512 !== expectedSha512) fail('installer-changed', 'the installer on disk is not the file whose hashes were verified');
  data = null;

  const outer = list(sevenZip, installerFile);
  if (outer.type !== 'Nsis') fail('installer-malformed', `the installer is not an NSIS installer (7-Zip reports ${JSON.stringify(outer.type)})`);
  const fixtureOuter = outer.entries.find(e => isFixturePath(e.path));
  if (fixtureOuter) fail('fixture-build', `the installer contains ${fixtureOuter.path}; it must never be released`);
  const payloads = outer.entries.filter(e => PAYLOAD_NAME.test(e.path));
  if (payloads.length !== 1 || payloads[0].path !== APP_PAYLOAD) fail('installer-malformed', `expected exactly one ${APP_PAYLOAD} in the installer, found ${JSON.stringify(payloads.map(e => e.path))}`);

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'hype-inspect-'));
  try {
    run7z(sevenZip, ['x', '-y', '-spd', '-sccUTF-8', `-o${path.join(work, 'nsis')}`, '--', installerFile, APP_PAYLOAD]);
    const payloadFile = path.join(work, 'nsis', ...APP_PAYLOAD.split('/'));
    if (!fs.existsSync(payloadFile)) fail('installer-malformed', `${APP_PAYLOAD} could not be extracted`);
    const inner = list(sevenZip, payloadFile);
    if (inner.type !== '7z') fail('installer-malformed', `${APP_PAYLOAD} is not a 7z archive`);
    const fixtureInner = inner.entries.find(e => isFixturePath(e.path));
    if (fixtureInner) fail('fixture-build', `the installer is an updater TEST build (payload contains ${fixtureInner.path}); it must never be released`);
    const asars = inner.entries.filter(e => e.path.toLowerCase() === 'resources/app.asar');
    if (asars.length !== 1 || asars[0].dir || asars[0].path !== 'resources/app.asar') fail('installer-malformed', 'expected exactly one resources/app.asar in the application payload');
    run7z(sevenZip, ['x', '-y', '-spd', '-sccUTF-8', `-o${path.join(work, 'app')}`, '--', payloadFile, 'resources/app.asar', 'resources/app-update.yml']);
    const asarFile = path.join(work, 'app', 'resources', 'app.asar');
    if (!fs.existsSync(asarFile) || fs.statSync(asarFile).size !== asars[0].size) fail('installer-malformed', 'resources/app.asar could not be extracted completely');
    const identity = checkAppAsar(asarFile, config, version);
    checkAppUpdateYml(path.join(work, 'app', 'resources', 'app-update.yml'), config);
    return { ...identity, sha512, testFixture: false };
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}
