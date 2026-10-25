// End-to-end tests for release-tool.mjs against a fake GitHub (test-fake-gh.mjs on PATH as `gh`, test-fake-fetch.mjs
// preloaded in place of fetch). Nothing here contacts GitHub: every result is SIMULATED evidence of the tool's logic,
// not proof of how real GitHub behaves. Uses this repository's own release-config.json, so the same file runs in the
// BETA and LIVE repositories. Needs the real 7z command (installers are inspected exactly as in a release; only the
// outer NSIS wrapper is stood in for, as in installer-inspection.test.mjs). Signing keys are generated per run and
// thrown away.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const HERE = path.dirname(new URL(import.meta.url).pathname);
const ROOT = path.resolve(HERE, '..', '..');
const config = JSON.parse(fs.readFileSync(path.join(ROOT, 'release-config.json'), 'utf8'));
const CH = config.channel;
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hype-rt-test-'));
const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');
const REAL_7Z = (spawnSync('sh', ['-c', 'command -v 7z'], { encoding: 'utf8' }).stdout || '').trim();
const GATE = { name: 'live-release', protection_rules: [{ type: 'required_reviewers', reviewers: [{ type: 'User' }] }] };

// Throwaway signing key for this run only.
const kp = crypto.generateKeyPairSync('ed25519');
const PUB = kp.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const sign = s => { const b = Buffer.from(JSON.stringify(s)); return JSON.stringify({ statement: b.toString('base64'), signature: crypto.sign(null, Buffer.concat([Buffer.from('HYPE-TOOLS-UPDATE-V1\n'), b]), kp.privateKey).toString('base64') }); };

// Installer laid out like electron-builder's (NSIS -> $PLUGINSDIR/app-64.7z -> resources/app.asar). The NSIS wrapper is
// a marker in front of a real 7z archive; the `7z` on the tool's PATH presents such files as Type = Nsis.
const MAGIC = 'MZ-FAKE-NSIS\n';
function asarBytes(files) {
  const root = { files: {} }, chunks = [];
  let offset = 0;
  for (const [p, text] of Object.entries(files)) {
    const data = Buffer.from(text), hash = sha256(data);
    root.files[p] = { size: data.length, offset: String(offset), integrity: { algorithm: 'SHA256', hash, blockSize: 4194304, blocks: [hash] } };
    chunks.push(data); offset += data.length;
  }
  const json = Buffer.from(JSON.stringify(root)), padded = Math.ceil(json.length / 4) * 4, header = Buffer.alloc(16 + padded);
  header.writeUInt32LE(4, 0); header.writeUInt32LE(8 + padded, 4); header.writeUInt32LE(4 + padded, 8); header.writeInt32LE(json.length, 12);
  json.copy(header, 16);
  return Buffer.concat([header, ...chunks]);
}
const run7z = (cwd, ...argv) => { const r = spawnSync(REAL_7Z, argv, { cwd, encoding: 'utf8' }); assert.equal(r.status, 0, r.stderr); };
const installers = new Map();
function installer(version) {
  if (installers.has(version)) return installers.get(version);
  const dir = tmp(), app = path.join(dir, 'app'), res = path.join(app, 'resources'), outer = path.join(dir, 'outer'), plugins = path.join(outer, '$PLUGINSDIR');
  fs.mkdirSync(res, { recursive: true }); fs.mkdirSync(plugins, { recursive: true });
  fs.writeFileSync(path.join(app, 'app.exe'), 'MZ app');
  fs.writeFileSync(path.join(res, 'app.asar'), asarBytes({
    'package.json': JSON.stringify({ name: `hype-tools-${CH}`, version, main: 'main.cjs' }),
    'build-channel.json': JSON.stringify({ schemaVersion: 1, channel: CH, version }),
    'main.cjs': '// app ' + crypto.randomBytes(8).toString('hex'),
  }));
  const [owner, repo] = config.repo.split('/');
  fs.writeFileSync(path.join(res, 'app-update.yml'), `owner: ${owner}\nrepo: ${repo}\nprovider: github\nreleaseType: release\nupdaterCacheDirName: x-updater\n`);
  run7z(app, 'a', '-bd', path.join(plugins, 'app-64.7z'), '.');
  run7z(outer, 'a', '-bd', path.join(dir, 'outer.7z'), '.');
  const file = path.join(dir, 'installer.exe');
  fs.writeFileSync(file, Buffer.concat([Buffer.from(MAGIC), fs.readFileSync(path.join(dir, 'outer.7z'))]));
  installers.set(version, file);
  return file;
}

let nextId = 1000;
// A release as the fake GitHub stores it. draft=false gives an already published, immutable release.
function release(version, { seq = 5, draft = true, prerelease = false, immutable = !draft } = {}) {
  const file = installer(version), data = fs.readFileSync(file);
  const name = config.installerTemplate.replace('{version}', version), sha = crypto.createHash('sha512').update(data).digest('base64');
  const yml = `version: ${version}\nfiles:\n  - url: ${name}\n    sha512: ${sha}\n    size: ${data.length}\npath: ${name}\nsha512: ${sha}\nreleaseDate: '2026-01-01T00:00:00.000Z'\n`;
  const stmt = sign({ appId: config.appId, channel: CH, version, sequence: seq, installerName: name, size: data.length, sha512: sha, issuedAt: '2026-01-01T00:00:00Z' });
  const asset = (n, buf, extra = {}) => ({ id: nextId++, name: n, size: buf.length, state: 'uploaded', updated_at: '2026-01-01T00:00:00Z', digest: 'sha256:' + sha256(buf), ...extra });
  return {
    tag_name: 'v' + version, draft, prerelease, immutable, target_commitish: 'main', html_url: `https://github.com/${config.repo}/releases/tag/v${version}`,
    published_at: draft ? null : '2026-01-01T00:00:00Z', publishOrder: draft ? 0 : nextId,
    assets: [asset(name, data, { contentFile: file }), asset('latest.yml', Buffer.from(yml), { content: Buffer.from(yml).toString('base64') }), asset('release-statement.json', Buffer.from(stmt), { content: Buffer.from(stmt).toString('base64') })],
  };
}
const entry = (version, sequence, status = 'published') => ({ tag: 'v' + version, version, sequence, status });

function workspace(key = PUB) {
  const d = tmp();
  for (const f of ['.github', 'release-config.json', 'README.md', 'keys', 'ledger']) fs.cpSync(path.join(ROOT, f), path.join(d, f), { recursive: true });
  fs.writeFileSync(path.join(d, 'keys/update-public-key.txt'), key + '\n');
  const bin = path.join(d, 'bin');
  fs.mkdirSync(bin);
  fs.copyFileSync(path.join(HERE, 'test-fake-gh.mjs'), path.join(bin, 'gh')); fs.chmodSync(path.join(bin, 'gh'), 0o755);
  fs.writeFileSync(path.join(bin, '7z'), `#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
const MAGIC = Buffer.from(${JSON.stringify(MAGIC)});
const args = process.argv.slice(2), at = args.indexOf('--') + 1, archive = args[at];
let target = archive, fake = false;
try { const b = fs.readFileSync(archive); if (b.subarray(0, MAGIC.length).equals(MAGIC)) { target = archive + '.inner.7z'; fs.writeFileSync(target, b.subarray(MAGIC.length)); fake = true; } } catch {}
const r = spawnSync(${JSON.stringify(REAL_7Z)}, [...args.slice(0, at), target, ...args.slice(at + 1)], { encoding: 'utf8', maxBuffer: 1 << 26 });
if (fake) fs.rmSync(target, { force: true });
let out = r.stdout || '';
if (fake && args[0] === 'l') out = out.replace(/^Type = 7z$/m, 'Type = Nsis').split(target).join(archive);
process.stdout.write(out); process.stderr.write(r.stderr || '');
process.exit(r.status === null ? 2 : r.status);
`, { mode: 0o755 });
  return d;
}

// Runs the real release-tool.mjs once. The child gets no GitHub token and cannot reach the real gh or the network.
function run(argv, { ledger = [], releases = [], faults = {}, latest, env = GATE, key } = {}) {
  const d = workspace(key), sf = path.join(d, 'state.json');
  const ledgerText = JSON.stringify({ schema: 1, releases: ledger }, null, 2) + '\n';
  fs.writeFileSync(path.join(d, 'ledger/releases.json'), ledgerText);
  const pubd = releases.filter(r => !r.draft && !r.prerelease).sort((x, y) => x.publishOrder - y.publishOrder);
  fs.writeFileSync(sf, JSON.stringify({ ledger: ledgerText, ledgerSha: 's0', releases, faults, env, latest: latest !== undefined ? latest : (pubd.at(-1) ? pubd.at(-1).tag_name : null), calls: [] }));
  const childEnv = { PATH: path.join(d, 'bin') + ':' + path.dirname(process.execPath) + ':/usr/bin:/bin', HOME: d, FAKE_GH_STATE: sf, GITHUB_REPOSITORY: config.repo };
  const r = spawnSync(process.execPath, ['--import', path.join(HERE, 'test-fake-fetch.mjs'), path.join(d, '.github/scripts/release-tool.mjs'), ...argv], { cwd: d, encoding: 'utf8', env: childEnv, timeout: 120000 });
  const state = JSON.parse(fs.readFileSync(sf, 'utf8'));
  fs.rmSync(d, { recursive: true, force: true });
  const text = r.stdout + r.stderr;
  return { code: r.status, text, state, ledger: JSON.parse(state.ledger).releases, result: (text.match(/result: .*/) || [''])[0] };
}
const ok = r => assert.equal(r.code, 0, r.text);
const failed = (r, code) => { assert.equal(r.code, 1, r.text); assert.match(r.result, new RegExp(`FAILED \\[${code}\\]`), r.text); };
const mutations = r => r.state.calls.filter(c => !/^release edit v\d+\.\d+\.\d+ --draft=false --latest$/.test(c));
const rel = (r, tag) => r.state.releases.find(x => x.tag_name === tag);
const latest = r => r.state.latest;

// Common history: v1.0.0 and v1.1.0 were published and verified; v1.2.0 (sequence 5) is the draft to publish.
const history = () => ({ ledger: [entry('1.0.0', 3), entry('1.1.0', 4)], releases: [release('1.0.0', { seq: 3, draft: false }), release('1.1.0', { seq: 4, draft: false }), release('1.2.0', { seq: 5 })] });
const publish = ['publish', '--tag', 'v1.2.0'];

test('the real 7z command is available', () => { assert.ok(REAL_7Z, '7z is required for these tests'); });

test('S1 successful publication: verified, recorded as published, latest is the new release, retention applied', () => {
  const r = run(publish, history());
  ok(r);
  assert.match(r.text, /post-publish checks passed/);
  assert.match(r.text, /GitHub digest compared for 3/);
  assert.deepEqual(r.ledger.find(e => e.tag === 'v1.2.0').status, 'published');
  assert.equal(latest(r), 'v1.2.0');
  assert.deepEqual(r.state.deleted, ['v1.0.0']);
  assert.equal(r.ledger.find(e => e.tag === 'v1.0.0').status, 'retired');
});

test('S2 public installer bytes differ from the verified draft: failed-verification, previous restored and read back', () => {
  const h = history();
  const r = run(publish, { ...h, faults: { publicContent: { [config.installerTemplate.replace('{version}', '1.2.0')]: Buffer.from('MZ tampered').toString('base64') } } });
  failed(r, 'post-publish-check');
  const e = r.ledger.find(x => x.tag === 'v1.2.0');
  assert.equal(e.status, 'failed-verification');
  assert.equal(e.failure.recovery, 'restored');
  assert.equal(e.failure.recoveryTarget, 'v1.1.0');
  assert.ok(e.failure.checks.some(c => /^size-mismatch: /.test(c)) && e.failure.checks.some(c => /^digest-mismatch: /.test(c)) && e.failure.checks.some(c => /^installer-changed: /.test(c)), JSON.stringify(e.failure.checks));
  assert.equal(latest(r), 'v1.1.0');
  assert.deepEqual(mutations(r), ['release edit v1.1.0 --latest']);
  assert.ok(rel(r, 'v1.2.0') && rel(r, 'v1.2.0').draft === false, 'the failed release stays public; nothing deletes it');
  assert.equal(r.state.deleted, undefined, 'retention did not run');
  assert.match(r.text, /RESTORED: \/releases\/latest read back as v1\.1\.0/);
  assert.match(r.text, /STILL PUBLIC/);
});

test('S3 GitHub digest of a published asset disagrees with the downloaded bytes', () => {
  const r = run(publish, { ...history(), faults: { publishedDigest: { tag: 'v1.2.0', name: 'latest.yml' } } });
  failed(r, 'post-publish-check');
  assert.match(r.text, /digest-mismatch: latest\.yml: public sha256 differs from GitHub's digest/);
  assert.equal(latest(r), 'v1.1.0');
});

test('S4 latest pointer not moved by the publish call enters the failure path (after re-reads)', () => {
  const r = run(publish, { ...history(), faults: { publishSkipsLatest: true } });
  failed(r, 'post-publish-check');
  assert.match(r.text, /latest-pointer: \/releases\/latest is v1\.1\.0, expected v1\.2\.0/);
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0').status, 'failed-verification');
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0').failure.recovery, 'restored');
});

test('S5 failed public download of latest.yml, or a network error on the statement, enters the failure path', () => {
  let r = run(publish, { ...history(), faults: { publicStatus: { 'latest.yml': 404 } } });
  failed(r, 'post-publish-check');
  assert.match(r.text, /download-failed: latest\.yml: HTTP 404/);
  r = run(publish, { ...history(), faults: { publicThrows: 'release-statement.json' } });
  failed(r, 'post-publish-check');
  assert.match(r.text, /download-failed: release-statement\.json: .*ECONNRESET/);
  assert.equal(latest(r), 'v1.1.0');
});

test('S6 release published without immutability is failed-verification, not healthy', () => {
  const r = run(publish, { ...history(), faults: { publishNotImmutable: true } });
  failed(r, 'post-publish-check');
  assert.match(r.text, /not-immutable: /);
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0').status, 'failed-verification');
});

test('S7 restoration command fails: reported, failed status kept, manual action named', () => {
  const r = run(publish, { ...history(), faults: { publicStatus: { 'latest.yml': 404 }, setLatestFails: true } });
  failed(r, 'post-publish-check');
  const e = r.ledger.find(x => x.tag === 'v1.2.0');
  assert.equal(e.status, 'failed-verification');
  assert.equal(e.failure.recovery, 'restore-failed');
  assert.equal(latest(r), 'v1.2.0');
  assert.match(r.text, /RECOVERY NOT CONFIRMED \(restore-failed\)/);
  assert.match(r.text, /MANUAL INTERVENTION REQUIRED: set the latest release to v1\.1\.0 yourself/);
  assert.doesNotMatch(r.text, /RESTORED:/);
});

test('S8 restoration accepted but the read-back disagrees, or cannot be read: restore-unverified', () => {
  let r = run(publish, { ...history(), faults: { publicStatus: { 'latest.yml': 404 }, setLatestNoop: true } });
  failed(r, 'post-publish-check');
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0').failure.recovery, 'restore-unverified');
  assert.match(r.text, /\/releases\/latest is v1\.2\.0, expected v1\.1\.0/);
  r = run(publish, { ...history(), faults: { publicStatus: { 'latest.yml': 404 }, latestReadFailsAfterRecovery: true } });
  failed(r, 'post-publish-check');
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0').failure.recovery, 'restore-unverified');
  assert.match(r.text, /could not read \/releases\/latest: .*503/);
  assert.match(r.text, /MANUAL INTERVENTION REQUIRED/);
});

test('S9 no previous known-good release: nothing invented, failed release taken out of latest and read back', () => {
  const r = run(publish, { ledger: [], releases: [release('1.2.0', { seq: 5 })], faults: { publicStatus: { 'release-statement.json': 500 } } });
  failed(r, 'post-publish-check');
  const e = r.ledger.find(x => x.tag === 'v1.2.0');
  assert.equal(e.failure.recovery, 'withdrawn');
  assert.equal(e.failure.recoveryTarget, null);
  assert.deepEqual(mutations(r), ['release edit v1.2.0 --prerelease']);
  assert.equal(latest(r), null);
  assert.equal(rel(r, 'v1.2.0').prerelease, true);
  assert.match(r.text, /WITHDRAWN FROM LATEST: there is no previous known-good release, so nothing was restored/);
  assert.doesNotMatch(r.text, /RESTORED:/);
});

test('S10 no previous known-good (only failed or legacy not-immutable history) and the withdrawal fails', () => {
  const ledger = [entry('1.0.0', 3, 'failed-verification'), entry('1.1.0', 4, 'not-immutable')];
  ledger[0].failure = { at: 'x', checks: ['latest-pointer: x'], recovery: 'withdrawn', recoveryTarget: null };
  const releases = [{ ...release('1.0.0', { seq: 3, draft: false }), prerelease: true }, release('1.1.0', { seq: 4, draft: false, immutable: false }), release('1.2.0', { seq: 5 })];
  let r = run(publish, { ledger, releases, faults: { publicStatus: { 'latest.yml': 404 } } });
  failed(r, 'post-publish-check');
  assert.deepEqual(mutations(r), ['release edit v1.2.0 --prerelease']);
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0').failure.recovery, 'withdraw-unverified', 'GitHub falls back to v1.1.0, which is not known-good');
  assert.match(r.text, /\/releases\/latest is v1\.1\.0, expected no latest release \(that release is not a known-good release\)/);
  r = run(publish, { ledger, releases, faults: { publicStatus: { 'latest.yml': 404 }, setPrereleaseFails: true } });
  failed(r, 'post-publish-check');
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0').failure.recovery, 'withdraw-failed');
  assert.match(r.text, /MANUAL INTERVENTION REQUIRED: take v1\.2\.0 out of \/releases\/latest yourself/);
});

test('S11 ledger write fails on the failure path: surfaced, not claimed as recorded, next release blocked', () => {
  const h = history();
  let r = run(publish, { ...h, faults: { publicStatus: { 'latest.yml': 404 }, ledgerPutFails: true } });
  failed(r, 'post-publish-check');
  assert.match(r.result, /ledger NOT updated/);
  assert.match(r.text, /LEDGER NOT UPDATED: .*409.*v1\.2\.0 is NOT durably recorded as failed-verification/);
  assert.doesNotMatch(r.text, /recorded as failed-verification \(recovery/);
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0'), undefined);
  assert.equal(latest(r), 'v1.1.0', 'restoration still happened');
  // The next release cannot be verified until the missing entry is added by hand.
  const after = run(['verify', '--tag', 'v1.3.0'], { ledger: h.ledger, releases: [...r.state.releases, release('1.3.0', { seq: 6 })] });
  failed(after, 'unrecorded-release');
  // A PUT that GitHub accepts but that does not stick is caught by the read-back.
  r = run(publish, { ...history(), faults: { publicStatus: { 'latest.yml': 404 }, ledgerPutDropped: true } });
  failed(r, 'post-publish-check');
  assert.match(r.text, /LEDGER NOT UPDATED: ledger read-back shows no entry for v1\.2\.0/);
});

test('S12 ledger write fails after a healthy publication: failure reported, retention not run', () => {
  const r = run(publish, { ...history(), faults: { ledgerPutFails: true } });
  failed(r, 'ledger-write');
  assert.match(r.text, /v1\.2\.0 is public and verified but NOT recorded/);
  assert.equal(r.state.deleted, undefined);
  assert.equal(latest(r), 'v1.2.0');
});

test('S13 transient ledger conflict is retried and succeeds', () => {
  const r = run(publish, { ...history(), faults: { ledgerPutFails: 1 } });
  ok(r);
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0').status, 'published');
});

test('S14 missing or unreadable GitHub data fails closed with diagnostics instead of crashing', () => {
  let r = run(publish, { ...history(), faults: { publishedNoAssets: 'v1.2.0' } });
  failed(r, 'post-publish-check');
  assert.match(r.text, /release-read: release data has no asset list/);
  r = run(publish, { ...history(), faults: { latestReadFails: 5 } }); // one read before publishing, then all four re-reads
  failed(r, 'post-publish-check');
  assert.match(r.text, /latest-read: .*503/);
  // A transient blip shorter than the re-read window is not a failure.
  r = run(publish, { ...history(), faults: { latestReadFails: 2 } });
  ok(r);
  r = run(publish, { ...history(), faults: { atomStatus: 500 } });
  failed(r, 'post-publish-check');
  assert.match(r.text, /atom-read: /);
});

test('S15 publish command errors: still a draft means nothing public; already public means it is checked as failed', () => {
  let r = run(publish, { ...history(), faults: { publishErrorBefore: true } });
  failed(r, 'publish-failed');
  assert.deepEqual(mutations(r), []);
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0'), undefined);
  r = run(publish, { ...history(), faults: { publishErrorAfter: true } });
  failed(r, 'post-publish-check');
  assert.match(r.text, /publish-command: /);
  assert.equal(r.ledger.find(x => x.tag === 'v1.2.0').status, 'failed-verification');
  assert.equal(latest(r), 'v1.1.0');
});

test('S16 dry runs make no changes', () => {
  let r = run([...publish, '--dry-run'], history());
  ok(r);
  assert.deepEqual(r.state.calls, []);
  assert.equal(r.state.ledgerPuts, undefined);
  assert.match(r.text, /latest goes back to v1\.1\.0, the previous known-good release/);
  r = run([...publish, '--dry-run'], { ledger: [], releases: [release('1.2.0', { seq: 5 })] });
  ok(r);
  assert.match(r.text, /no previous known-good release exists, so v1\.2\.0 would be marked as a prerelease/);
  assert.deepEqual(r.state.calls, []);
  const ledger = ['1.0.0', '1.1.0', '1.2.0', '1.3.0'].map((v, i) => entry(v, i + 1));
  r = run(['retention', '--tag', 'v1.3.0', '--dry-run'], { ledger, releases: ['1.0.0', '1.1.0', '1.2.0', '1.3.0'].map((v, i) => release(v, { seq: i + 1, draft: false })) });
  ok(r);
  assert.deepEqual(r.state.calls, []);
});

test('S17 retention never deletes or keeps failed releases as healthy', () => {
  const ledger = [entry('1.0.0', 1), entry('1.1.0', 2, 'failed-verification'), entry('1.2.0', 3), entry('1.3.0', 4), entry('1.4.0', 5, 'failed-verification')];
  for (const i of [1, 4]) ledger[i].failure = { at: 'x', checks: ['size-mismatch: x'], recovery: 'restored', recoveryTarget: 'v1.0.0' };
  const releases = ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0'].map((v, i) => release(v, { seq: i + 1, draft: false }));
  const r = run(['retention', '--tag', 'v1.4.0'], { ledger, releases });
  ok(r);
  assert.deepEqual(r.state.deleted, ['v1.0.0']);
  assert.match(r.text, /keep \["v1\.3\.0","v1\.2\.0"\]/);
  assert.match(r.text, /failed verification \(never deleted here\) \["v1\.1\.0","v1\.4\.0"\]/);
  assert.ok(rel(r, 'v1.1.0') && rel(r, 'v1.4.0'));
});

test('S18 a failed release burns its tag, version and sequence', () => {
  const ledger = [entry('1.1.0', 4), { ...entry('1.2.0', 5, 'failed-verification'), failure: { at: 'x', checks: ['latest-pointer: x'], recovery: 'restored', recoveryTarget: 'v1.1.0' } }];
  const pub = [release('1.1.0', { seq: 4, draft: false }), release('1.2.0', { seq: 5, draft: false })];
  const verify = (version, seq) => run(['verify', '--tag', 'v' + version], { ledger, releases: [...pub.filter(p => p.tag_name !== 'v' + version), release(version, { seq })] });
  failed(verify('1.2.0', 9), 'tag-reused');
  failed(verify('1.1.5', 9), 'version-not-newer');
  failed(verify('1.3.0', 5), 'stmt-replay');
  ok(verify('1.3.0', 6));
});

test('S19 existing schema-1 ledgers with the older statuses still work', () => {
  const ledger = [entry('0.9.0', 1, 'retired'), entry('1.0.0', 2, 'not-immutable'), entry('1.1.0', 3)];
  const releases = [release('1.0.0', { seq: 2, draft: false, immutable: false }), release('1.1.0', { seq: 3, draft: false }), release('1.2.0', { seq: 5 })];
  const r = run(publish, { ledger, releases, latest: 'v1.1.0' });
  ok(r);
  assert.equal(r.ledger.length, 4);
  assert.deepEqual(r.ledger.slice(0, 3), ledger);
});

test('S20 a changed draft, invalid inputs and the unconfigured key still block publication', () => {
  let r = run(publish, { ...history(), faults: { changeDraftOnList: 2 } });
  failed(r, 'draft-changed');
  assert.deepEqual(r.state.calls, []);
  failed(run(['publish', '--tag', 'v1.2'], history()), 'bad-tag');
  failed(run(['publish'], history()), 'usage');
  const h = history();
  h.releases[2].assets.push({ id: nextId++, name: 'extra.txt', size: 5, state: 'uploaded', content: Buffer.from('hello').toString('base64') });
  failed(run(publish, h), 'asset-not-allowed');
  r = run(publish, { ...history(), key: 'UNSET' });
  failed(r, 'no-public-key');
  assert.deepEqual(r.state.calls, []);
});

test('S21 published releases missing from the ledger block verification', () => {
  const h = history();
  failed(run(publish, { ...h, ledger: h.ledger.slice(0, 1) }), 'unrecorded-release');
});

test(`S22 approval gate for this channel (${CH})`, () => {
  if (config.approvalEnvironment) {
    failed(run(publish, { ...history(), env: null }), 'gate-unverifiable');
    failed(run(publish, { ...history(), env: { name: config.approvalEnvironment, protection_rules: [] } }), 'gate-missing');
    ok(run([...publish, '--dry-run'], history()));
  } else {
    const r = run([...publish, '--dry-run'], { ...history(), env: null });
    ok(r);
    assert.match(r.text, /no approval environment required/);
  }
});
