import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  validateConfig, versionFromTag, checkAssetAllowlist, parseUpdateYml, checkMetadata, verifyStatement,
  validateLedger, lastPublished, planRetention, semverCmp, ReleaseError, LEDGER_STATUSES, previousGood, unrecordedReleases,
  verifyPublication, recoverLatest, failureEntry, incidentReport, redact,
} from './lib.mjs';

const live = validateConfig({ schema: 1, channel: 'live', appId: 'com.example.app.live', productName: 'P LIVE', repo: 'o/live', tagPattern: '^v(\\d+\\.\\d+\\.\\d+)$', installerTemplate: 'P-LIVE-Setup-{version}.exe', metadataName: 'latest.yml', statementName: 'release-statement.json', publicKeyFile: 'keys/update-public-key.txt', prerelease: false, retention: 2, approvalEnvironment: 'live-release' });
const beta = validateConfig({ ...live, channel: 'beta', appId: 'com.example.app.beta', productName: 'P BETA', repo: 'o/beta', installerTemplate: 'P-BETA-Setup-{version}.exe', approvalEnvironment: null });
const code = (f) => { try { f(); } catch (e) { assert.ok(e instanceof ReleaseError, String(e)); return e.code; } assert.fail('expected failure'); };

const kp = () => crypto.generateKeyPairSync('ed25519');
const pubB64 = k => k.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const sign = (s, k) => { const b = Buffer.from(JSON.stringify(s)); return JSON.stringify({ statement: b.toString('base64'), signature: crypto.sign(null, Buffer.concat([Buffer.from('HYPE-TOOLS-UPDATE-V1\n'), b]), k.privateKey).toString('base64') }); };
const facts = { size: 1000, sha512: 'AAAA' };
const stmt = (o = {}) => ({ appId: live.appId, channel: 'live', version: '1.2.0', sequence: 5, installerName: 'P-LIVE-Setup-1.2.0.exe', size: 1000, sha512: 'AAAA', issuedAt: '2026-01-01T00:00:00Z', ...o });
const exp = { installer: 'P-LIVE-Setup-1.2.0.exe', metadata: 'latest.yml', statement: 'release-statement.json' };

test('config rules', () => {
  assert.equal(code(() => validateConfig({ ...live, prerelease: true })), 'bad-config');
  assert.equal(code(() => validateConfig({ ...live, approvalEnvironment: null })), 'bad-config');
  assert.equal(code(() => validateConfig({ ...live, appId: 'com.example.app.beta' })), 'bad-config');
  assert.equal(code(() => validateConfig({ ...live, retention: 1 })), 'bad-config');
});
test('tags', () => {
  assert.equal(versionFromTag(live, 'v1.2.0'), '1.2.0');
  for (const t of ['1.2.0', 'v1.2', 'v1.2.0-beta.1', 'v1.2.0 ', 'v01.2.0x', 'v1.2.0\n', '../v1.2.0']) assert.equal(code(() => versionFromTag(live, t)), 'bad-tag', t);
});
test('semver compare', () => { assert.ok(semverCmp('1.10.0', '1.9.0') > 0); assert.equal(semverCmp('1.0.0', '1.0.0'), 0); });

const asset = (name, size = 10, state = 'uploaded') => ({ name, size, state });
test('asset allowlist', () => {
  const ok = [asset(exp.installer), asset('latest.yml'), asset('release-statement.json')];
  checkAssetAllowlist(live, '1.2.0', ok);
  assert.equal(code(() => checkAssetAllowlist(live, '1.2.0', [...ok, asset('extra.txt')])), 'asset-not-allowed');
  assert.equal(code(() => checkAssetAllowlist(live, '1.2.0', [...ok, asset('P-LIVE-Setup-1.2.0.exe.blockmap')])), 'asset-not-allowed');
  assert.equal(code(() => checkAssetAllowlist(live, '1.2.0', ok.slice(1))), 'asset-missing');
  assert.equal(code(() => checkAssetAllowlist(live, '1.2.0', [...ok, ok[0]])), 'asset-duplicate');
  assert.equal(code(() => checkAssetAllowlist(live, '1.2.0', [asset(exp.installer, 0), ...ok.slice(1)])), 'asset-size');
  assert.equal(code(() => checkAssetAllowlist(live, '1.2.0', [asset(exp.installer, 3e9), ...ok.slice(1)])), 'asset-too-large');
  assert.equal(code(() => checkAssetAllowlist(live, '1.2.0', [asset(exp.installer, 10, 'starter'), ...ok.slice(1)])), 'asset-state');
  assert.equal(code(() => checkAssetAllowlist(live, '1.2.0', [asset('P-BETA-Setup-1.2.0.exe'), ...ok.slice(1)])), 'asset-not-allowed');
});

const YML = `version: 1.2.0\nfiles:\n  - url: P-LIVE-Setup-1.2.0.exe\n    sha512: AAAA\n    size: 1000\npath: P-LIVE-Setup-1.2.0.exe\nsha512: AAAA\nreleaseDate: '2026-01-01T00:00:00.000Z'\n`;
test('update yml strict parse and cross-check', () => {
  const y = parseUpdateYml(YML);
  checkMetadata(live, '1.2.0', exp, y, facts);
  assert.equal(code(() => checkMetadata(live, '1.3.0', exp, y, facts)), 'meta-version');
  assert.equal(code(() => checkMetadata(live, '1.2.0', exp, y, { ...facts, size: 5 })), 'meta-size');
  assert.equal(code(() => checkMetadata(live, '1.2.0', exp, y, { ...facts, sha512: 'BBBB' })), 'meta-hash');
  assert.equal(code(() => checkMetadata(live, '1.2.0', { ...exp, installer: 'other.exe' }, y, facts)), 'meta-name');
  assert.equal(code(() => parseUpdateYml(YML + 'extra: 1\n')), 'yml-unknown-key');
  assert.equal(code(() => parseUpdateYml(YML.replace('version: 1.2.0\n', 'version: 1.2.0\nversion: 1.2.1\n'))), 'yml-duplicate-key');
  assert.equal(code(() => parseUpdateYml(YML.replace('    size: 1000\n', ''))), 'yml-missing-key');
  assert.equal(code(() => parseUpdateYml(YML + '  - url: second.exe\n')), 'yml-shape');
  assert.equal(code(() => parseUpdateYml(YML.replace('files:\n', 'files: x\n'))), 'yml-shape');
  assert.equal(code(() => parseUpdateYml('!!python/object: x\n')), 'yml-shape');
});

test('statement verification fails closed', () => {
  const k = kp(), other = kp();
  const ok = sign(stmt(), k);
  assert.equal(verifyStatement(ok, pubB64(k), live, '1.2.0', exp, facts, 4).sequence, 5);
  assert.equal(code(() => verifyStatement(ok, '', live, '1.2.0', exp, facts, 4)), 'no-public-key');
  assert.equal(code(() => verifyStatement(ok, 'UNSET', live, '1.2.0', exp, facts, 4)), 'no-public-key');
  assert.equal(code(() => verifyStatement(ok, pubB64(other), live, '1.2.0', exp, facts, 4)), 'stmt-signature');
  assert.equal(code(() => verifyStatement(sign(stmt({ channel: 'beta' }), k), pubB64(k), live, '1.2.0', exp, facts, 4)), 'stmt-channel');
  assert.equal(code(() => verifyStatement(sign(stmt({ appId: beta.appId }), k), pubB64(k), live, '1.2.0', exp, facts, 4)), 'stmt-app');
  assert.equal(code(() => verifyStatement(sign(stmt({ version: '1.2.1' }), k), pubB64(k), live, '1.2.0', exp, facts, 4)), 'stmt-version');
  assert.equal(code(() => verifyStatement(sign(stmt({ installerName: 'x.exe' }), k), pubB64(k), live, '1.2.0', exp, facts, 4)), 'stmt-name');
  assert.equal(code(() => verifyStatement(sign(stmt({ size: 1 }), k), pubB64(k), live, '1.2.0', exp, facts, 4)), 'stmt-size');
  assert.equal(code(() => verifyStatement(sign(stmt({ sha512: 'CCCC' }), k), pubB64(k), live, '1.2.0', exp, facts, 4)), 'stmt-hash');
  assert.equal(code(() => verifyStatement(ok, pubB64(k), live, '1.2.0', exp, facts, 5)), 'stmt-replay');
  assert.equal(code(() => verifyStatement(sign({ ...stmt(), extra: 1 }, k), pubB64(k), live, '1.2.0', exp, facts, 4)), 'stmt-shape');
  assert.equal(code(() => verifyStatement('garbage', pubB64(k), live, '1.2.0', exp, facts, 4)), 'stmt-envelope');
  const e = JSON.parse(ok); e.statement = Buffer.from(JSON.stringify(stmt({ sequence: 99 }))).toString('base64');
  assert.equal(code(() => verifyStatement(JSON.stringify(e), pubB64(k), live, '1.2.0', exp, facts, 4)), 'stmt-signature');
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.equal(code(() => verifyStatement(ok, rsa.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'), live, '1.2.0', exp, facts, 4)), 'no-public-key');
});

const L = (...r) => validateLedger({ schema: 1, releases: r.map(([tag, sequence, status = 'published']) => ({ tag, version: tag.slice(1), sequence, status })) });
const R = (tag, immutable = true, draft = false) => ({ tag_name: tag, immutable, draft });
test('ledger', () => {
  assert.deepEqual(lastPublished(L()), { sequence: 0, version: '0.0.0' });
  assert.deepEqual(lastPublished(L(['v1.0.0', 3], ['v1.1.0', 4])), { sequence: 4, version: '1.1.0' });
  assert.equal(code(() => validateLedger({ schema: 1, releases: [{ tag: 'v1.0.0', version: '1.0.0', sequence: 1, status: 'x' }] })), 'bad-ledger');
  assert.equal(code(() => L(['v1.0.0', 1], ['v1.0.0', 2])), 'bad-ledger');
});
test('retention: newest two kept, older owned removed, unowned never touched', () => {
  const ledger = L(['v1.0.0', 1], ['v1.1.0', 2], ['v1.2.0', 3], ['v1.3.0', 4]);
  const live4 = ['v1.0.0', 'v1.1.0', 'v1.2.0', 'v1.3.0', 'v0.9.0'].map(t => R(t));
  const p = planRetention({ ledger, liveReleases: live4, keep: 2 });
  assert.deepEqual(p.keep.sort(), ['v1.2.0', 'v1.3.0']);
  assert.deepEqual(p.delete.sort(), ['v1.0.0', 'v1.1.0']);
  assert.deepEqual(p.unowned, ['v0.9.0']);
});
test('retention: nothing is deleted unless two newer healthy releases exist', () => {
  const ledger = L(['v1.0.0', 1], ['v1.1.0', 2], ['v1.2.0', 3]);
  const p = planRetention({ ledger, liveReleases: [R('v1.0.0'), R('v1.1.0'), R('v1.2.0', false)], keep: 2 });
  assert.deepEqual(p.delete, []);
  assert.deepEqual(p.notImmutableOwned, ['v1.2.0']);
  const p2 = planRetention({ ledger: L(['v1.0.0', 1], ['v1.1.0', 2]), liveReleases: [R('v1.0.0'), R('v1.1.0')], keep: 2 });
  assert.deepEqual(p2.delete, []);
});
test('retention: drafts, retired and missing releases are ignored', () => {
  const ledger = L(['v1.0.0', 1, 'retired'], ['v1.1.0', 2], ['v1.2.0', 3], ['v1.3.0', 4]);
  const p = planRetention({ ledger, liveReleases: [R('v1.1.0'), R('v1.2.0'), R('v1.3.0'), R('v1.4.0', true, true)], keep: 2 });
  assert.deepEqual(p.delete, ['v1.1.0']);
  assert.deepEqual(p.unowned, []);
});

// ---- failed-verification, recovery targets and post-publication checks (in-memory GitHub; no network) ----
const F = (o = {}) => ({ at: '2026-10-25T00:00:00Z', checks: ['latest-pointer: x'], recovery: 'restored', recoveryTarget: 'v1.0.0', ...o });
test('ledger: schema-1 ledgers with the older statuses stay valid; failed-verification is accepted', () => {
  assert.deepEqual(LEDGER_STATUSES.slice(0, 3), ['published', 'retired', 'not-immutable']);
  validateLedger({ schema: 1, releases: [] });
  validateLedger(L(['v0.9.0', 1, 'retired'], ['v1.0.0', 2, 'not-immutable'], ['v1.1.0', 3]));
  validateLedger({ schema: 1, releases: [{ tag: 'v1.0.0', version: '1.0.0', sequence: 1, status: 'published', publishedAt: 'x', installerSha512: 'AAAA' }] });
  validateLedger({ schema: 1, releases: [{ tag: 'v1.2.0', version: '1.2.0', sequence: 5, status: 'failed-verification' }] });
  validateLedger({ schema: 1, releases: [{ tag: 'v1.2.0', version: '1.2.0', sequence: 5, status: 'failed-verification', failure: F() }] });
  for (const recovery of ['restore-failed', 'restore-unverified', 'withdrawn', 'withdraw-failed', 'withdraw-unverified']) validateLedger({ schema: 1, releases: [{ tag: 'v1', version: '1.0.0', sequence: 1, status: 'failed-verification', failure: F({ recovery, recoveryTarget: null }) }] });
});
test('ledger: malformed failure records and unknown statuses are rejected', () => {
  const one = (o, status = 'failed-verification') => code(() => validateLedger({ schema: 1, releases: [{ tag: 'v1.2.0', version: '1.2.0', sequence: 5, status, ...o }] }));
  assert.equal(one({}, 'failed'), 'bad-ledger');
  assert.equal(one({}, 'pending-verification'), 'bad-ledger');
  assert.equal(one({ failure: F() }, 'published'), 'bad-ledger');
  assert.equal(one({ failure: F({ recovery: 'deleted' }) }), 'bad-ledger');
  assert.equal(one({ failure: F({ checks: [] }) }), 'bad-ledger');
  assert.equal(one({ failure: F({ checks: Array(21).fill('x') }) }), 'bad-ledger');
  assert.equal(one({ failure: F({ checks: ['x'.repeat(301)] }) }), 'bad-ledger');
  assert.equal(one({ failure: { ...F(), token: 'x' } }), 'bad-ledger');
  assert.equal(one({ failure: 'bad' }), 'bad-ledger');
  assert.equal(code(() => validateLedger({ schema: 2, releases: [] })), 'bad-ledger');
});
test('a failed release still raises the version and sequence floor (no reuse)', () => {
  assert.deepEqual(lastPublished(L(['v1.0.0', 3], ['v1.1.0', 4, 'failed-verification'])), { sequence: 4, version: '1.1.0' });
  assert.deepEqual(lastPublished(L(['v1.0.0', 3, 'retired'], ['v1.1.0', 4, 'not-immutable'])), { sequence: 4, version: '1.1.0' });
});
const RL = (tag, o = {}) => ({ tag_name: tag, draft: false, prerelease: false, immutable: true, ...o });
test('previous known-good: newest healthy, live, immutable, non-prerelease release; never a failed one; never invented', () => {
  const ledger = L(['v1.0.0', 1], ['v1.1.0', 2], ['v1.2.0', 3, 'failed-verification'], ['v1.3.0', 4, 'not-immutable']);
  const rels = ['v1.0.0', 'v1.1.0', 'v1.2.0', 'v1.3.0'].map(t => RL(t));
  assert.deepEqual(previousGood(ledger, rels), { tag: 'v1.1.0', version: '1.1.0', sequence: 2 });
  assert.equal(previousGood(ledger, rels, 2).tag, 'v1.0.0');
  assert.equal(previousGood(ledger, [RL('v1.0.0'), RL('v1.1.0', { immutable: false })]).tag, 'v1.0.0');
  assert.equal(previousGood(ledger, [RL('v1.0.0'), RL('v1.1.0', { prerelease: true })]).tag, 'v1.0.0');
  assert.equal(previousGood(ledger, [RL('v1.1.0', { draft: true })]), null);
  assert.equal(previousGood(L(['v1.0.0', 1, 'failed-verification']), [RL('v1.0.0')]), null);
  assert.equal(previousGood(L(), []), null);
});
test('unrecorded published releases are found; drafts, other tag shapes and recorded ones are not', () => {
  const ledger = L(['v1.0.0', 1, 'failed-verification']);
  assert.deepEqual(unrecordedReleases(live, ledger, [RL('v1.0.0'), RL('v1.1.0'), RL('v1.2.0', { draft: true }), RL('sandbox-test')]), ['v1.1.0']);
});
test('retention: failed releases are never kept as healthy and never deleted', () => {
  const ledger = L(['v1.0.0', 1], ['v1.1.0', 2, 'failed-verification'], ['v1.2.0', 3], ['v1.3.0', 4], ['v1.4.0', 5, 'failed-verification']);
  const p = planRetention({ ledger, liveReleases: ['v1.0.0', 'v1.1.0', 'v1.2.0', 'v1.3.0', 'v1.4.0'].map(t => R(t)), keep: 2 });
  assert.deepEqual(p.keep, ['v1.3.0', 'v1.2.0']);
  assert.deepEqual(p.delete, ['v1.0.0']);
  assert.deepEqual(p.failedOwned, ['v1.1.0', 'v1.4.0']);
  // Only failed releases newer than the two healthy ones: nothing is deleted.
  const p2 = planRetention({ ledger: L(['v1.0.0', 1], ['v1.1.0', 2], ['v1.2.0', 3, 'failed-verification'], ['v1.3.0', 4, 'failed-verification']), liveReleases: ['v1.0.0', 'v1.1.0', 'v1.2.0', 'v1.3.0'].map(t => R(t)), keep: 2 });
  assert.deepEqual(p2.delete, []);
  assert.deepEqual(p2.keep.sort(), ['v1.0.0', 'v1.1.0']);
});
test('redact strips token-shaped text and bounds length', () => {
  const pat = 'github' + '_pat_' + 'A1b2C3d4E5', classic = 'gh' + 'p_' + 'abcdefghijklmnopqrstuvwxyz0123';
  const out = redact(`failed ${pat} and ${classic} Authorization: Bearer abc.def`);
  assert.doesNotMatch(out, /A1b2C3|abcdefghij|abc\.def/);
  assert.equal(redact('x'.repeat(500)).length, 300);
});

// An in-memory GitHub for the post-publication logic.
const sha256hex = b => crypto.createHash('sha256').update(b).digest('hex');
const sha512b64 = b => crypto.createHash('sha512').update(b).digest('base64');
function world({ previous = 'v1.1.0' } = {}) {
  const k = kp(), version = '1.2.0', tag = 'v1.2.0';
  const inst = Buffer.from('MZ installer bytes'), name = exp.installer;
  const yml = Buffer.from(`version: ${version}\nfiles:\n  - url: ${name}\n    sha512: ${sha512b64(inst)}\n    size: ${inst.length}\npath: ${name}\nsha512: ${sha512b64(inst)}\nreleaseDate: '2026-01-01T00:00:00.000Z'\n`);
  const st = Buffer.from(sign(stmt({ size: inst.length, sha512: sha512b64(inst) }), k));
  const files = { [name]: inst, 'latest.yml': yml, 'release-statement.json': st };
  const assets = Object.entries(files).map(([n, b], i) => ({ id: 10 + i, name: n, size: b.length, state: 'uploaded', digest: 'sha256:' + sha256hex(b) }));
  const v = {
    exp, snapshot: assets.map(({ id, name, size }) => ({ id, name, size })), statement: { sequence: 5 }, installer: { size: inst.length, sha512: sha512b64(inst) },
    expected: Object.fromEntries(Object.entries(files).map(([n, b]) => [n, { size: b.length, sha256: sha256hex(b) }])), lastSequence: 4, publicKey: pubB64(k),
  };
  const releases = { [tag]: { tag_name: tag, draft: false, prerelease: false, immutable: true, assets, published_at: 't' } };
  if (previous) releases[previous] = { tag_name: previous, draft: false, prerelease: false, immutable: true, assets: [{ name: 'P-LIVE-Setup-1.1.0.exe' }, { name: 'latest.yml' }, { name: 'release-statement.json' }] };
  const w = { latest: tag, served: { ...files }, calls: [], faults: {} };
  w.io = {
    getRelease: async t => { if (w.faults.releaseRead) throw new Error('HTTP 502'); return releases[t]; },
    getLatest: async () => { if (w.faults.latestReads && w.faults.latestReads-- > 0) throw new Error('HTTP 503'); return w.latest ? { tag_name: w.latest } : null; },
    download: async url => { const n = decodeURIComponent(url.split('/').pop()), b = w.served[n]; return b ? { ok: true, status: 200, size: b.length, sha256: sha256hex(b), sha512: sha512b64(b), body: b } : { ok: false, status: 404 }; },
    atomFirstTag: async () => tag,
    setLatest: async t => { w.calls.push('latest ' + t); if (w.faults.setLatest) throw new Error('HTTP 422'); if (!w.faults.noop) w.latest = t; },
    setPrerelease: async t => { w.calls.push('prerelease ' + t); releases[t].prerelease = true; w.latest = null; },
    sleep: async () => {},
  };
  return { w, v, tag, version, releases, args: { io: w.io, config: live, repo: 'o/live', tag, version, v } };
}
test('verifyPublication: a healthy publication has no problems and compares every digest', async () => {
  const { args } = world();
  const r = await verifyPublication(args);
  assert.deepEqual(r.problems, []);
  assert.equal(r.digests, 3);
});
test('verifyPublication: tampered public bytes, wrong flags and a stale latest are all reported together', async () => {
  const { w, args, releases, tag } = world();
  w.served[exp.installer] = Buffer.from('MZ other bytes!!!!');
  w.served['latest.yml'] = undefined;
  Object.assign(releases[tag], { immutable: false, prerelease: true });
  w.latest = 'v1.1.0';
  const codes = (await verifyPublication(args)).problems.map(p => p.split(':')[0]);
  for (const c of ['prerelease-flag', 'not-immutable', 'latest-pointer', 'download-failed', 'digest-mismatch', 'installer-changed', 'installer-mismatch']) assert.ok(codes.includes(c), `${c} in ${codes}`);
});
test('verifyPublication: a short latest outage is re-read; a missing release is reported, not dereferenced', async () => {
  const a = world(); a.w.faults.latestReads = 2;
  assert.deepEqual((await verifyPublication(a.args)).problems, []);
  const b = world(); b.w.faults.releaseRead = true;
  assert.ok((await verifyPublication(b.args)).problems.some(p => p.startsWith('release-read: ')));
  const c = world(); c.releases[c.tag] = undefined;
  assert.ok((await verifyPublication(c.args)).problems.includes('release-read: GitHub returned no release data'));
});
test('recoverLatest: restored only when the read-back confirms it', async () => {
  const prev = { tag: 'v1.1.0', version: '1.1.0', sequence: 4 };
  let x = world();
  let r = await recoverLatest({ io: x.w.io, config: live, tag: x.tag, previous: prev });
  assert.equal(r.outcome, 'restored'); assert.equal(x.w.latest, 'v1.1.0');
  x = world(); x.w.faults.setLatest = true;
  r = await recoverLatest({ io: x.w.io, config: live, tag: x.tag, previous: prev });
  assert.equal(r.outcome, 'restore-failed'); assert.equal(x.w.latest, 'v1.2.0');
  x = world(); x.w.faults.noop = true;
  assert.equal((await recoverLatest({ io: x.w.io, config: live, tag: x.tag, previous: prev })).outcome, 'restore-unverified');
  x = world(); x.releases['v1.1.0'].immutable = false;
  assert.equal((await recoverLatest({ io: x.w.io, config: live, tag: x.tag, previous: prev })).outcome, 'restore-unverified');
});
test('recoverLatest: with no previous known-good release, the failed one is withdrawn from latest, never replaced by a guess', async () => {
  const x = world({ previous: null });
  const r = await recoverLatest({ io: x.w.io, config: live, tag: x.tag, previous: null });
  assert.equal(r.outcome, 'withdrawn'); assert.equal(r.target, null);
  assert.deepEqual(x.w.calls, ['prerelease v1.2.0']);
  const y = world({ previous: null }); y.w.io.setPrerelease = async () => { throw new Error('HTTP 422'); };
  assert.equal((await recoverLatest({ io: y.w.io, config: live, tag: y.tag, previous: null })).outcome, 'withdraw-failed');
});
test('failure entry is small, valid in the ledger and reported honestly', async () => {
  const x = world();
  const recovery = { outcome: 'restore-failed', target: 'v1.1.0', detail: 'HTTP 422', steps: ['making v1.1.0 latest FAILED: HTTP 422'], checks: [] };
  const e = failureEntry({ tag: x.tag, version: x.version, v: x.v, published: { publishedAt: 't' }, problems: Array(30).fill('size-mismatch: ' + 'gh' + 's_' + 'abcdefghijklmnopqrstuvwxyz'), recovery, at: 'now' });
  validateLedger({ schema: 1, releases: [e] });
  assert.equal(e.failure.checks.length, 20);
  assert.doesNotMatch(JSON.stringify(e), /abcdefghij/);
  const text = incidentReport({ repo: 'o/live', tag: x.tag, published: { publishedAt: 't' }, problems: ['size-mismatch: x'], recovery, previous: { tag: 'v1.1.0' }, latestBefore: 'v1.1.0', ledgerError: 'HTTP 409' }).join('\n');
  assert.match(text, /RECOVERY NOT CONFIRMED \(restore-failed\)/);
  assert.match(text, /LEDGER NOT UPDATED: HTTP 409/);
  assert.match(text, /MANUAL INTERVENTION REQUIRED: set the latest release to v1\.1\.0 yourself \(gh release edit v1\.1\.0 --repo o\/live --latest\)/);
  assert.doesNotMatch(text, /RESTORED:|recorded as failed-verification \(recovery/);
});
test('verifyPublication: public bytes are compared with the verified draft even when GitHub gives no digest', async () => {
  const { w, args, releases, tag } = world();
  for (const a of releases[tag].assets) delete a.digest;
  w.served['latest.yml'] = Buffer.from(w.served['latest.yml'].toString().replace('2026-01-01', '2026-01-02'));
  const r = await verifyPublication(args);
  assert.deepEqual(r.problems, ['digest-mismatch: latest.yml: public sha256 differs from the verified draft']);
  assert.equal(r.digests, 0);
});
