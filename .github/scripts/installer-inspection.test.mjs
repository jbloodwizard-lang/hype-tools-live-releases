// Tests for installer-inspection.mjs. Needs the real 7z command (7-Zip): the application payload and app.asar are
// built and read with it exactly as in a release. The NSIS wrapper is the one part that cannot be produced on the
// runner (no NSIS compiler there), so a small stand-in for 7z presents "MZ-FAKE-NSIS" files as NSIS installers whose
// contents are a real 7z archive. Real electron-builder installers were checked separately (see Issue #37).
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { validateConfig, ReleaseError } from './lib.mjs';
import { inspectInstaller, expectedPackageName, parseSltListing, FIXTURE_FILE, CHANNEL_FILE, APP_PAYLOAD } from './installer-inspection.mjs';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const ROOT = path.resolve(HERE, '..', '..');
const live = validateConfig({ schema: 1, channel: 'live', appId: 'com.hypetools.desktop.live', productName: 'HYPE TOOLS LIVE', repo: 'jbloodwizard-lang/hype-tools-live-releases', tagPattern: '^v(\\d+\\.\\d+\\.\\d+)$', installerTemplate: 'HYPE-TOOLS-LIVE-Setup-{version}.exe', metadataName: 'latest.yml', statementName: 'release-statement.json', publicKeyFile: 'keys/update-public-key.txt', prerelease: false, retention: 2, approvalEnvironment: 'live-release' });
const beta = validateConfig({ ...live, channel: 'beta', appId: 'com.hypetools.desktop.beta', productName: 'HYPE TOOLS BETA', repo: 'jbloodwizard-lang/hype-tools-beta-releases', installerTemplate: 'HYPE-TOOLS-BETA-Setup-{version}.exe', approvalEnvironment: null });
const CONFIGS = { beta, live };

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hype-inspect-test-'));
const code = f => { try { f(); } catch (e) { assert.ok(e instanceof ReleaseError, String(e && e.stack)); return e.code; } assert.fail('expected failure'); };
const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const real7z = (cwd, ...argv) => { const r = spawnSync('7z', argv, { cwd, encoding: 'utf8' }); assert.equal(r.status, 0, `7z ${argv.join(' ')}: ${r.stderr}`); };

// Stand-in for 7z: a file that starts with MAGIC is a real 7z archive behind a marker and is listed as Type = Nsis.
const MAGIC = Buffer.from('MZ-FAKE-NSIS\n');
const FAKE_7Z = path.join(tmp(), 'fake-7z.mjs');
fs.writeFileSync(FAKE_7Z, `#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
const MAGIC = Buffer.from(${JSON.stringify(MAGIC.toString())});
const args = process.argv.slice(2), at = args.indexOf('--') + 1, archive = args[at];
let target = archive, fake = false;
try { const b = fs.readFileSync(archive); if (b.subarray(0, MAGIC.length).equals(MAGIC)) { target = archive + '.inner.7z'; fs.writeFileSync(target, b.subarray(MAGIC.length)); fake = true; } } catch {}
const r = spawnSync('7z', [...args.slice(0, at), target, ...args.slice(at + 1)], { encoding: 'utf8' });
if (fake) fs.rmSync(target, { force: true });
let out = r.stdout || '';
if (fake && args[0] === 'l') out = out.replace(/^Type = 7z$/m, 'Type = Nsis').split(target).join(archive);
process.stdout.write(out); process.stderr.write(r.stderr || '');
process.exit(r.status === null ? 2 : r.status);
`, { mode: 0o755 });

// ASAR as electron-builder writes it: pickled header size, pickled JSON tree with SHA-256 integrity records, data.
function asarBytes(files, tamper) {
  const root = { files: {} }, chunks = [];
  let offset = 0;
  for (const [p, text] of Object.entries(files)) {
    const parts = p.split('/'), data = Buffer.from(text), hash = sha256(data);
    let dir = root;
    for (const part of parts.slice(0, -1)) dir = (dir.files[part] = dir.files[part] || { files: {} });
    dir.files[parts.at(-1)] = { size: data.length, offset: String(offset), integrity: { algorithm: 'SHA256', hash, blockSize: 4194304, blocks: [hash] } };
    chunks.push(data); offset += data.length;
  }
  if (tamper) tamper(root);
  const json = Buffer.from(JSON.stringify(root)), padded = Math.ceil(json.length / 4) * 4, header = Buffer.alloc(16 + padded);
  header.writeUInt32LE(4, 0); header.writeUInt32LE(8 + padded, 4); header.writeUInt32LE(4 + padded, 8); header.writeInt32LE(json.length, 12);
  json.copy(header, 16);
  return Buffer.concat([header, ...chunks]);
}
const appFiles = (channel, version, extra = {}) => ({
  'package.json': JSON.stringify({ name: `hype-tools-${channel}`, version, main: 'main.cjs' }),
  [CHANNEL_FILE]: JSON.stringify({ schemaVersion: 1, channel, version }),
  'main.cjs': '// app',
  ...extra,
});
const updateYml = repo => `owner: ${repo.split('/')[0]}\nrepo: ${repo.split('/')[1]}\nprovider: github\nreleaseType: release\nupdaterCacheDirName: x-updater\n`;

// Builds an installer laid out like electron-builder's: NSIS -> $PLUGINSDIR/app-64.7z -> resources/app.asar.
function makeInstaller(channel, version, o = {}) {
  const dir = tmp(), app = path.join(dir, 'app'), res = path.join(app, 'resources'), outer = path.join(dir, 'outer'), plugins = path.join(outer, '$PLUGINSDIR');
  fs.mkdirSync(res, { recursive: true }); fs.mkdirSync(plugins, { recursive: true });
  fs.writeFileSync(path.join(app, `HYPE-TOOLS-${channel.toUpperCase()}.exe`), 'MZ app');
  if (o.asar !== null) fs.writeFileSync(path.join(res, 'app.asar'), o.asar || asarBytes(o.files || appFiles(channel, version, o.extra), o.tamper));
  if (o.yml !== null) fs.writeFileSync(path.join(res, 'app-update.yml'), o.yml || updateYml(CONFIGS[channel].repo));
  for (const [p, text] of Object.entries(o.unpacked || {})) { const f = path.join(res, 'app.asar.unpacked', p); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, text); }
  for (const name of o.payloads || ['app-64.7z']) real7z(app, 'a', '-bd', path.join(plugins, name), '.');
  if (o.corruptPayload) { const f = path.join(plugins, 'app-64.7z'), b = fs.readFileSync(f); fs.writeFileSync(f, b.subarray(0, b.length - 40)); }
  fs.writeFileSync(path.join(plugins, 'System.dll'), 'dll');
  for (const [p, text] of Object.entries(o.outerExtra || {})) fs.writeFileSync(path.join(outer, p), text);
  const outer7z = path.join(dir, 'outer.7z');
  real7z(outer, 'a', '-bd', outer7z, '.');
  const file = path.join(dir, o.name || CONFIGS[channel].installerTemplate.replace('{version}', version));
  fs.writeFileSync(file, Buffer.concat([o.notNsis ? Buffer.from('MZ') : MAGIC, fs.readFileSync(outer7z)]));
  return file;
}
const inspect = (file, config, version, opts = {}) => inspectInstaller(file, config, version, { sevenZip: FAKE_7Z, ...opts });

test('the real 7z command is available (the release runner must have it)', () => {
  const r = spawnSync('7z', ['i'], { encoding: 'utf8' });
  assert.ok(!r.error, '7z is not installed: installer inspection would fail closed on this machine');
  assert.match(r.stdout, /7-Zip/);
  assert.match(r.stdout, /\bNsis\b/i, 'this 7z build cannot read NSIS installers');
});

test('valid BETA and LIVE installers are accepted with their packaged identity', () => {
  for (const ch of ['beta', 'live']) {
    const file = makeInstaller(ch, '1.2.3');
    const r = inspect(file, CONFIGS[ch], '1.2.3');
    assert.deepEqual({ ...r, sha512: undefined }, { name: `hype-tools-${ch}`, channel: ch, version: '1.2.3', testFixture: false, sha512: undefined });
    assert.equal(r.sha512, crypto.createHash('sha512').update(fs.readFileSync(file)).digest('base64'));
    // Bound to the verified bytes.
    assert.ok(inspect(file, CONFIGS[ch], '1.2.3', { expectedSha512: r.sha512 }));
  }
});

test("this repository's own release-config.json maps to its packaged app name", () => {
  const config = validateConfig(JSON.parse(fs.readFileSync(path.join(ROOT, 'release-config.json'), 'utf8')));
  assert.equal(expectedPackageName(config), `hype-tools-${config.channel}`);
  assert.equal(inspect(makeInstaller(config.channel, '2.0.0'), config, '2.0.0').channel, config.channel);
});

test('an updater test-fixture installer is rejected', () => {
  for (const ch of ['beta', 'live']) assert.equal(code(() => inspect(makeInstaller(ch, '1.2.3', { extra: { [FIXTURE_FILE]: '{"schemaVersion":1}' } }), CONFIGS[ch], '1.2.3')), 'fixture-build');
});

test('a renamed test-fixture installer is still rejected, wherever the marker sits', () => {
  // Built under another name, then renamed to the normal release name and to something unrelated.
  const original = makeInstaller('beta', '1.2.3', { name: 'HYPE-TOOLS-BETA-TESTBUILD-Setup-1.2.3.exe', extra: { [FIXTURE_FILE]: '{}' } });
  for (const name of ['HYPE-TOOLS-BETA-Setup-1.2.3.exe', 'setup.exe', 'notes.txt']) {
    const renamed = path.join(path.dirname(original), name);
    fs.copyFileSync(original, renamed);
    assert.equal(code(() => inspect(renamed, beta, '1.2.3')), 'fixture-build', name);
  }
  for (const extra of [{ ['src/main/' + FIXTURE_FILE]: '{}' }, { 'UPDATE-TEST-FIXTURE.JSON': '{}' }]) assert.equal(code(() => inspect(makeInstaller('beta', '1.2.3', { extra }), beta, '1.2.3')), 'fixture-build');
  assert.equal(code(() => inspect(makeInstaller('live', '1.2.3', { unpacked: { [FIXTURE_FILE]: '{}' } }), live, '1.2.3')), 'fixture-build');
  assert.equal(code(() => inspect(makeInstaller('live', '1.2.3', { outerExtra: { [FIXTURE_FILE]: '{}' } }), live, '1.2.3')), 'fixture-build');
});

test('channel, version or feed mismatches between the installer and the release are rejected', () => {
  const liveInstaller = makeInstaller('live', '1.2.3');
  assert.equal(code(() => inspect(liveInstaller, beta, '1.2.3')), 'identity-mismatch');
  assert.equal(code(() => inspect(liveInstaller, live, '1.2.4')), 'identity-mismatch');
  // Package name says BETA but the stamped channel file says LIVE.
  const mixed = makeInstaller('beta', '1.2.3', { files: { ...appFiles('beta', '1.2.3'), [CHANNEL_FILE]: JSON.stringify({ schemaVersion: 1, channel: 'live', version: '1.2.3' }) } });
  assert.equal(code(() => inspect(mixed, beta, '1.2.3')), 'identity-mismatch');
  const staleStamp = makeInstaller('beta', '1.2.3', { files: { ...appFiles('beta', '1.2.3'), [CHANNEL_FILE]: JSON.stringify({ schemaVersion: 1, channel: 'beta', version: '1.2.2' }) } });
  assert.equal(code(() => inspect(staleStamp, beta, '1.2.3')), 'identity-mismatch');
  assert.equal(code(() => inspect(makeInstaller('beta', '1.2.3', { yml: updateYml(live.repo) }), beta, '1.2.3')), 'identity-mismatch');
});

test('missing or malformed packaged identity or app.asar is rejected', () => {
  const v = (o, ch = 'beta') => code(() => inspect(makeInstaller(ch, '1.2.3', o), CONFIGS[ch], '1.2.3'));
  const { 'package.json': _p, ...noPkg } = appFiles('beta', '1.2.3');
  const { [CHANNEL_FILE]: _c, ...noStamp } = appFiles('beta', '1.2.3');
  assert.equal(v({ files: noPkg }), 'identity-missing');
  assert.equal(v({ files: noStamp }), 'identity-missing');
  assert.equal(v({ files: { ...appFiles('beta', '1.2.3'), 'package.json': '{oops' } }), 'identity-malformed');
  assert.equal(v({ files: { ...appFiles('beta', '1.2.3'), [CHANNEL_FILE]: '[]' } }), 'identity-malformed');
  assert.equal(v({ tamper: r => { r.files['package.json'].integrity.hash = '0'.repeat(64); } }), 'identity-malformed');
  assert.equal(v({ tamper: r => { delete r.files[CHANNEL_FILE].integrity; } }), 'identity-malformed');
  assert.equal(v({ tamper: r => { r.files['package.json'].unpacked = true; } }), 'identity-malformed');
  assert.equal(v({ tamper: r => { r.files['main.cjs'].offset = '99999'; } }), 'asar-malformed');
  assert.equal(v({ asar: crypto.randomBytes(2048) }), 'asar-malformed');
  assert.equal(v({ asar: Buffer.from('x') }), 'asar-malformed');
  assert.equal(v({ asar: asarBytes(appFiles('beta', '1.2.3')).subarray(0, 100) }), 'asar-malformed');
  assert.equal(v({ asar: null }), 'installer-malformed');
  assert.equal(v({ yml: null }), 'identity-missing');
});

test('missing, unreadable or malformed installers fail closed', () => {
  const dir = tmp();
  assert.equal(code(() => inspect(path.join(dir, 'HYPE-TOOLS-BETA-Setup-1.2.3.exe'), beta, '1.2.3')), 'installer-unreadable');
  fs.writeFileSync(path.join(dir, 'empty.exe'), '');
  assert.equal(code(() => inspect(path.join(dir, 'empty.exe'), beta, '1.2.3')), 'installer-malformed');
  fs.writeFileSync(path.join(dir, 'text.exe'), 'not an installer');
  assert.equal(code(() => inspect(path.join(dir, 'text.exe'), beta, '1.2.3')), 'installer-malformed');
  fs.writeFileSync(path.join(dir, 'mz.exe'), Buffer.concat([Buffer.from('MZ'), crypto.randomBytes(4096)]));
  assert.ok(['installer-unreadable', 'installer-malformed'].includes(code(() => inspect(path.join(dir, 'mz.exe'), beta, '1.2.3'))));
  // A 7z archive with an MZ prefix is not an NSIS installer.
  assert.ok(['installer-unreadable', 'installer-malformed'].includes(code(() => inspect(makeInstaller('beta', '1.2.3', { notNsis: true }), beta, '1.2.3'))));
  assert.equal(code(() => inspect(makeInstaller('beta', '1.2.3', { payloads: [] }), beta, '1.2.3')), 'installer-malformed');
  assert.equal(code(() => inspect(makeInstaller('beta', '1.2.3', { payloads: ['app-32.7z', 'app-64.7z'] }), beta, '1.2.3')), 'installer-malformed');
  assert.equal(code(() => inspect(makeInstaller('beta', '1.2.3', { corruptPayload: true }), beta, '1.2.3')), 'installer-unreadable');
});

test('a missing inspection tool or a changed file fails closed', () => {
  const file = makeInstaller('beta', '1.2.3');
  assert.equal(code(() => inspectInstaller(file, beta, '1.2.3', { sevenZip: path.join(tmp(), 'no-such-7z') })), 'inspect-tool-missing');
  assert.equal(code(() => inspect(file, beta, '1.2.3', { expectedSha512: crypto.createHash('sha512').update('other').digest('base64') })), 'installer-changed');
  assert.equal(code(() => inspect(file, beta, '1.2')), 'inspect-usage');
  assert.equal(code(() => expectedPackageName({ ...beta, installerTemplate: 'setup-{version}.msi' })), 'inspect-config');
});

test('7z listings are parsed strictly', () => {
  assert.equal(code(() => parseSltListing('garbage')), 'installer-malformed');
  const r = parseSltListing('--\nPath = x.exe\nType = Nsis\n\n----------\nPath = $PLUGINSDIR\\app-64.7z\nSize = 5\nAttributes = \n\nPath = d\nFolder = +\n');
  assert.equal(r.type, 'Nsis');
  assert.deepEqual(r.entries, [{ path: APP_PAYLOAD, dir: false, size: 5 }, { path: 'd', dir: true, size: null }]);
});

test('release-tool verifies the installer payload during draft verification, so verify and publish both enforce it', () => {
  const src = fs.readFileSync(path.join(HERE, 'release-tool.mjs'), 'utf8');
  assert.match(src, /^import \{ inspectInstaller \} from '\.\/installer-inspection\.mjs';$/m);
  const verify = src.slice(src.indexOf('async function verifyDraft'), src.indexOf('function gateCheck'));
  assert.match(verify, /inspectInstaller\(path\.join\(dir, exp\.installer\), config, version, \{ expectedSha512: facts\[exp\.installer\]\.sha512 \}\)/);
  assert.ok(verify.indexOf('inspectInstaller(') < verify.indexOf('return {'));
  const publish = src.slice(src.indexOf('async function publish'), src.indexOf('async function retention'));
  assert.ok(publish.indexOf('await verifyDraft(ctx)') < publish.indexOf("'release', 'edit'"));
});
