// Pure helpers for the release manager. No network, no secrets, no third-party packages.
import crypto from 'node:crypto';

export class ReleaseError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
export const fail = (code, message) => { throw new ReleaseError(code, message); };

const PREFIX = Buffer.from('HYPE-TOOLS-UPDATE-V1\n', 'utf8');
const STATEMENT_KEYS = ['appId', 'channel', 'version', 'sequence', 'installerName', 'size', 'sha512', 'issuedAt'];
const SEMVER = /^\d+\.\d+\.\d+$/;
const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
export const MAX_INSTALLER_BYTES = 1_500_000_000; // GitHub asset limit is 2 GiB; stay well below
export const MAX_SMALL_FILE_BYTES = 1_000_000;

export function semverCmp(a, b) {
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
}

export function validateConfig(c) {
  const need = ['schema', 'channel', 'appId', 'productName', 'repo', 'tagPattern', 'installerTemplate', 'metadataName', 'statementName', 'publicKeyFile', 'prerelease', 'retention', 'approvalEnvironment'];
  for (const k of need) if (!(k in c)) fail('bad-config', `missing ${k}`);
  if (c.schema !== 1) fail('bad-config', 'schema');
  if (!['beta', 'live'].includes(c.channel)) fail('bad-config', 'channel');
  if (c.prerelease !== false) fail('bad-config', 'prerelease must be false (channels are separated by repository)');
  if (!Number.isInteger(c.retention) || c.retention < 2) fail('bad-config', 'retention must be >= 2');
  if (c.channel === 'live' && c.approvalEnvironment !== 'live-release') fail('bad-config', 'live requires the live-release environment');
  if (!c.installerTemplate.includes('{version}')) fail('bad-config', 'installerTemplate');
  if (c.channel === 'beta' && !/beta/.test(c.appId)) fail('bad-config', 'beta appId');
  if (c.channel === 'live' && !/live/.test(c.appId)) fail('bad-config', 'live appId');
  return c;
}

export function versionFromTag(config, tag) {
  const m = new RegExp(config.tagPattern).exec(tag);
  if (!m) fail('bad-tag', `tag ${JSON.stringify(tag)} does not match ${config.tagPattern}`);
  return m[1];
}

export function expectedAssets(config, version) {
  return { installer: config.installerTemplate.replaceAll('{version}', version), metadata: config.metadataName, statement: config.statementName };
}

// Release assets must be exactly the allowlist: no extras, no duplicates, no missing.
export function checkAssetAllowlist(config, version, assets) {
  const exp = expectedAssets(config, version);
  const want = new Set([exp.installer, exp.metadata, exp.statement]);
  const seen = new Set();
  for (const a of assets) {
    if (!want.has(a.name)) fail('asset-not-allowed', `unexpected asset ${JSON.stringify(a.name)}`);
    if (seen.has(a.name)) fail('asset-duplicate', a.name);
    seen.add(a.name);
    if (a.state !== 'uploaded') fail('asset-state', `${a.name} state ${a.state}`);
    if (!Number.isSafeInteger(a.size) || a.size < 1) fail('asset-size', `${a.name} is empty`);
    const limit = a.name === exp.installer ? MAX_INSTALLER_BYTES : MAX_SMALL_FILE_BYTES;
    if (a.size > limit) fail('asset-too-large', `${a.name} ${a.size} > ${limit}`);
  }
  for (const n of want) if (!seen.has(n)) fail('asset-missing', n);
  return exp;
}

const unq = v => { v = v.trim(); return (v.length > 1 && (v[0] === "'" || v[0] === '"') && v.at(-1) === v[0]) ? v.slice(1, -1) : v; };

// Strict reader for the electron-builder update metadata shape. Anything unknown is an error.
export function parseUpdateYml(text) {
  const top = {}, files = [];
  let inFiles = false, cur = null;
  const TOP = new Set(['version', 'files', 'path', 'sha512', 'releaseDate']);
  const ITEM = new Set(['url', 'sha512', 'size', 'blockMapSize']);
  for (const raw of text.replace(/\r\n/g, '\n').split('\n')) {
    if (!raw.trim()) continue;
    let m;
    if ((m = /^([A-Za-z0-9]+):(?: (.*))?$/.exec(raw))) {
      if (!TOP.has(m[1])) fail('yml-unknown-key', m[1]);
      if (m[1] in top) fail('yml-duplicate-key', m[1]);
      inFiles = m[1] === 'files'; cur = null;
      if (inFiles) { if (m[2]) fail('yml-shape', 'files must be a list'); top.files = files; } else top[m[1]] = unq(m[2] ?? '');
    } else if (inFiles && (m = /^  - ([A-Za-z0-9]+): (.+)$/.exec(raw))) {
      if (!ITEM.has(m[1])) fail('yml-unknown-key', m[1]);
      cur = { [m[1]]: unq(m[2]) }; files.push(cur);
    } else if (inFiles && cur && (m = /^    ([A-Za-z0-9]+): (.+)$/.exec(raw))) {
      if (!ITEM.has(m[1])) fail('yml-unknown-key', m[1]);
      if (m[1] in cur) fail('yml-duplicate-key', m[1]);
      cur[m[1]] = unq(m[2]);
    } else fail('yml-shape', `cannot parse line ${JSON.stringify(raw.slice(0, 60))}`);
  }
  for (const k of ['version', 'files', 'path', 'sha512', 'releaseDate']) if (!(k in top)) fail('yml-missing-key', k);
  if (files.length !== 1) fail('yml-shape', 'exactly one file expected');
  const f = files[0];
  for (const k of ['url', 'sha512', 'size']) if (!(k in f)) fail('yml-missing-key', `files[0].${k}`);
  if (!/^\d+$/.test(f.size)) fail('yml-shape', 'size');
  return { version: top.version, path: top.path, sha512: top.sha512, releaseDate: top.releaseDate, file: { url: f.url, sha512: f.sha512, size: Number(f.size) } };
}

export function checkMetadata(config, version, exp, yml, installerFacts) {
  if (yml.version !== version) fail('meta-version', `${yml.version} vs ${version}`);
  if (yml.path !== exp.installer || yml.file.url !== exp.installer) fail('meta-name', 'installer name does not match the allowlist name');
  if (yml.sha512 !== yml.file.sha512) fail('meta-hash', 'top-level and file sha512 differ');
  if (yml.file.size !== installerFacts.size) fail('meta-size', `${yml.file.size} vs ${installerFacts.size}`);
  if (yml.file.sha512 !== installerFacts.sha512) fail('meta-hash', 'metadata sha512 does not match the uploaded installer');
}

export function verifyStatement(envelopeText, publicKeyB64, config, version, exp, installerFacts, lastSequence) {
  if (!publicKeyB64 || publicKeyB64 === 'UNSET' || !B64.test(publicKeyB64)) fail('no-public-key', 'update public key is not configured; publishing is blocked until the owner adds it');
  let env;
  try { env = JSON.parse(envelopeText); } catch { fail('stmt-envelope', 'not JSON'); }
  if (!env || typeof env.statement !== 'string' || typeof env.signature !== 'string') fail('stmt-envelope', 'statement or signature missing');
  if (!B64.test(env.statement) || !B64.test(env.signature)) fail('stmt-envelope', 'not base64');
  const bytes = Buffer.from(env.statement, 'base64'), sig = Buffer.from(env.signature, 'base64');
  if (sig.length !== 64) fail('stmt-signature', 'signature length');
  let pub;
  try { pub = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' }); } catch { fail('no-public-key', 'public key is not valid SPKI'); }
  if (pub.asymmetricKeyType !== 'ed25519') fail('no-public-key', 'public key is not Ed25519');
  if (!crypto.verify(null, Buffer.concat([PREFIX, bytes]), pub, sig)) fail('stmt-signature', 'signature does not verify against the configured key');
  let s;
  try { s = JSON.parse(bytes.toString('utf8')); } catch { fail('stmt-shape', 'not JSON'); }
  if (!s || typeof s !== 'object' || Array.isArray(s) || Object.keys(s).sort().join() !== [...STATEMENT_KEYS].sort().join()) fail('stmt-shape', 'unexpected key set');
  if (![s.appId, s.channel, s.version, s.installerName, s.sha512, s.issuedAt].every(v => typeof v === 'string')) fail('stmt-shape', 'types');
  if (!Number.isSafeInteger(s.sequence) || s.sequence < 1 || !Number.isSafeInteger(s.size) || s.size < 1) fail('stmt-shape', 'numeric types');
  if (!SEMVER.test(s.version)) fail('stmt-shape', 'version');
  if (s.appId !== config.appId) fail('stmt-app', `${s.appId} != ${config.appId}`);
  if (s.channel !== config.channel) fail('stmt-channel', `${s.channel} != ${config.channel}`);
  if (s.version !== version) fail('stmt-version', `${s.version} != ${version}`);
  if (s.installerName !== exp.installer) fail('stmt-name', `${s.installerName} != ${exp.installer}`);
  if (s.size !== installerFacts.size) fail('stmt-size', 'size');
  if (s.sha512 !== installerFacts.sha512) fail('stmt-hash', 'sha512');
  if (s.sequence <= lastSequence) fail('stmt-replay', `sequence ${s.sequence} <= last published ${lastSequence}`);
  return s;
}

// Ledger statuses. schema stays 1; failed-verification is an additional value, so older ledgers still validate.
//   published           made public and every post-publication check passed (the only healthy status)
//   failed-verification made public, but a post-publication check failed; never healthy, never deleted by retention
//   retired             removed by retention (tag kept, name never reused)
//   not-immutable       legacy value written by older versions of this tool; not healthy
export const LEDGER_STATUSES = ['published', 'retired', 'not-immutable', 'failed-verification'];
export const HEALTHY_STATUS = 'published';
// What happened to the `latest` pointer after a failed verification (stored in failure.recovery).
export const RECOVERY_OUTCOMES = ['restored', 'restore-failed', 'restore-unverified', 'withdrawn', 'withdraw-failed', 'withdraw-unverified'];
const MAX_FAILURE_CHECKS = 20, MAX_CHECK_TEXT = 300;

function validateFailure(r) {
  const f = r.failure;
  const bad = m => fail('bad-ledger', `entry ${JSON.stringify(r.tag)}: failure ${m}`);
  if (r.status !== 'failed-verification') bad('is only allowed on failed-verification entries');
  if (!f || typeof f !== 'object' || Array.isArray(f)) bad('must be an object');
  const keys = Object.keys(f).sort().join();
  if (keys !== 'at,checks,recovery,recoveryTarget') bad(`has keys ${keys}`);
  if (typeof f.at !== 'string' || !f.at) bad('at');
  if (!Array.isArray(f.checks) || f.checks.length < 1 || f.checks.length > MAX_FAILURE_CHECKS || !f.checks.every(c => typeof c === 'string' && c.length <= MAX_CHECK_TEXT)) bad('checks');
  if (!RECOVERY_OUTCOMES.includes(f.recovery)) bad('recovery');
  if (f.recoveryTarget !== null && typeof f.recoveryTarget !== 'string') bad('recoveryTarget');
}

export function validateLedger(l) {
  if (!l || l.schema !== 1 || !Array.isArray(l.releases)) fail('bad-ledger', 'shape');
  const tags = new Set();
  for (const r of l.releases) {
    if (!r || typeof r.tag !== 'string' || !SEMVER.test(r.version) || !Number.isSafeInteger(r.sequence) || !LEDGER_STATUSES.includes(r.status)) fail('bad-ledger', `entry ${JSON.stringify(r && r.tag)}`);
    if ('failure' in r) validateFailure(r);
    if (tags.has(r.tag)) fail('bad-ledger', `duplicate ${r.tag}`);
    tags.add(r.tag);
  }
  return l;
}

// Highest sequence and version ever recorded, whatever the status. Failed, retired and legacy entries count, so a
// failed release's version, sequence and tag can never be used again.
export function lastPublished(ledger) {
  let seq = 0, ver = '0.0.0';
  for (const r of ledger.releases) { if (r.sequence > seq) seq = r.sequence; if (semverCmp(r.version, ver) > 0) ver = r.version; }
  return { sequence: seq, version: ver };
}

// Published (non-draft) releases on GitHub that match this channel's tag pattern but have no ledger entry. They appear
// when a publication finished but its ledger write did not; until the ledger is fixed, their version and sequence are
// unknown here, so verification refuses to continue.
export function unrecordedReleases(config, ledger, liveReleases) {
  const known = new Set(ledger.releases.map(r => r.tag));
  const pattern = new RegExp(config.tagPattern);
  return liveReleases.filter(r => !r.draft && pattern.test(r.tag_name) && !known.has(r.tag_name)).map(r => r.tag_name);
}

// The newest ledger release that is healthy and still live as an immutable, non-prerelease release: the only safe
// target when `latest` has to be moved back. null when there is none (nothing is invented).
export function previousGood(ledger, liveReleases, beforeSequence = Infinity) {
  const live = new Map(liveReleases.filter(r => !r.draft).map(r => [r.tag_name, r]));
  const good = ledger.releases
    .filter(r => r.status === HEALTHY_STATUS && r.sequence < beforeSequence && live.has(r.tag) && live.get(r.tag).immutable === true && live.get(r.tag).prerelease === false)
    .sort((a, b) => b.sequence - a.sequence)[0];
  return good ? { tag: good.tag, version: good.version, sequence: good.sequence } : null;
}

// Ownership-aware retention: only releases recorded in the ledger as published may be removed,
// and only when at least `keep` newer owned releases are live and immutable. Unknown releases are reported, never touched.
// failed-verification (and legacy not-immutable) entries are neither kept as healthy nor ever deleted.
export function planRetention({ ledger, liveReleases, keep }) {
  const live = new Map(liveReleases.filter(r => !r.draft).map(r => [r.tag_name, r]));
  const owned = ledger.releases.filter(r => r.status === HEALTHY_STATUS && live.has(r.tag)).sort((a, b) => b.sequence - a.sequence);
  const healthy = owned.filter(r => live.get(r.tag).immutable === true);
  const keepSet = new Set(owned.slice(0, keep).map(r => r.tag));
  const del = [];
  for (const r of owned.slice(keep)) {
    const newerHealthy = healthy.filter(h => h.sequence > r.sequence).length;
    if (newerHealthy >= keep) del.push(r.tag);
  }
  const unowned = [...live.keys()].filter(t => !ledger.releases.some(r => r.tag === t));
  const failedOwned = ledger.releases.filter(r => r.status === 'failed-verification' && live.has(r.tag)).map(r => r.tag);
  return { keep: [...keepSet], delete: del, unowned, failedOwned, notImmutableOwned: owned.filter(r => live.get(r.tag).immutable !== true).map(r => r.tag) };
}

// ---------------------------------------------------------------------------------------------------------------
// Post-publication verification and recovery. No network of its own: every GitHub or HTTP call goes through `io`, so
// the logic runs unchanged against the real gh CLI (release-tool.mjs) and against in-memory fakes (tests).
//   io.getRelease(tag)     release JSON, or throws
//   io.getLatest()         { tag_name } of /releases/latest, null when GitHub reports no latest release, or throws
//   io.download(url)       { ok, status, size, sha256, sha512, body } (body only for small files), or throws
//   io.atomFirstTag()      tag of the first releases.atom entry, or null, or throws
//   io.setLatest(tag)      make `tag` the latest release, throws on failure
//   io.setPrerelease(tag)  mark `tag` as a prerelease (takes it out of /releases/latest), throws on failure
//   io.sleep(ms)           wait (a no-op in tests)
// ---------------------------------------------------------------------------------------------------------------

// Patterns are assembled from pieces so check-static.mjs does not flag this file as containing a secret.
const TOKENISH = [new RegExp('github' + '_pat_[A-Za-z0-9_]+', 'g'), new RegExp('gh' + '[pousr]_[A-Za-z0-9]{8,}', 'g'), /\b(authorization|bearer|token)\b[=: ]+(bearer )?\S+/gi];
// Short, secret-free text for logs and the ledger.
export function redact(text, max = MAX_CHECK_TEXT) {
  let s = String(text ?? '').replace(/\s+/g, ' ').trim();
  for (const r of TOKENISH) s = s.replace(r, '[redacted]');
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}
const errText = e => redact(e && e.code ? `${e.code}: ${e.message}` : (e && (e.stderr || e.message)) || e, 200);
const assetKey = a => ({ id: a.id, name: a.name, size: a.size });

// Public-read retry policy: up to `attempts` tries (default 4) with waits of delayMs, 2*delayMs, 3*delayMs between them
// (default 3 s, so at most 18 s per URL). Retried: thrown network errors and HTTP 404 (assets can lag just after
// publication), 408, 425, 429 and 5xx. Any other status fails at once.
export const TRANSIENT_HTTP = status => [404, 408, 425, 429].includes(status) || (status >= 500 && status <= 599);
// `judge(result)` returns { value } for a final good answer, or { retry, error, value } otherwise. The answer of the
// last try is returned as is: { value, error, thrown, tries }.
async function publicRead(io, read, judge, attempts, delayMs) {
  let last = { error: 'not attempted', tries: 0 };
  for (let i = 0; i < attempts; i++) {
    let j;
    try { j = judge(await read()); last = { value: j.value, error: j.error || null, thrown: false, tries: i + 1 }; }
    catch (e) { j = { retry: true }; last = { error: errText(e), thrown: true, tries: i + 1 }; }
    if (!j.retry || i === attempts - 1) break;
    await io.sleep(delayMs * (i + 1));
  }
  return last;
}

// `v` is the verified draft returned by verifyDraft: snapshot, expected per-asset size and sha256, installer facts,
// statement sequence floor and public key. Collects every problem (not only the first) as "code: detail" strings.
// The release and `latest` reads are retried a few times so that a briefly stale API answer is not reported as a failure.
export async function verifyPublication({ io, config, repo, tag, version, v, attempts = 4, delayMs = 3000 }) {
  let problems = [], pub = null;
  for (let i = 0; i < attempts; i++) {
    problems = []; pub = null;
    const add = (code, text) => problems.push(`${code}: ${text}`);
    let readError = null;
    try { pub = await io.getRelease(tag); } catch (e) { readError = errText(e); }
    if (readError) { add('release-read', readError); pub = null; }
    else if (!pub || typeof pub !== 'object') { add('release-read', 'GitHub returned no release data'); pub = null; }
    else if (!Array.isArray(pub.assets)) { add('release-read', 'release data has no asset list'); pub = null; }
    if (pub) {
      if (pub.tag_name !== tag) add('release-read', `asked for ${tag}, GitHub returned ${pub.tag_name}`);
      if (pub.draft !== false) add('still-draft', 'release is still a draft');
      if (pub.prerelease !== config.prerelease) add('prerelease-flag', `prerelease is ${pub.prerelease}, expected ${config.prerelease}`);
      if (pub.immutable !== true) add('not-immutable', 'release is NOT immutable: enable Immutable releases in repository settings');
      const got = pub.assets.map(assetKey).sort((x, y) => x.id - y.id);
      const want = v.snapshot.map(assetKey).sort((x, y) => x.id - y.id);
      if (JSON.stringify(got) !== JSON.stringify(want)) add('asset-set-changed', 'published asset set differs from the verified draft');
      for (const a of pub.assets) if (a.state !== 'uploaded') add('asset-state', `${a.name} state ${a.state}`);
    }
    try {
      const latest = await io.getLatest();
      if (!latest || latest.tag_name !== tag) add('latest-pointer', `/releases/latest is ${latest ? latest.tag_name : 'missing'}, expected ${tag}`);
    } catch (e) { add('latest-read', errText(e)); }
    if (!problems.length || i === attempts - 1) break;
    await io.sleep(delayMs * (i + 1));
  }
  const add = (code, text) => problems.push(`${code}: ${text}`);
  const api = new Map(pub ? pub.assets.map(a => [a.name, a]) : []);
  const names = [v.exp.installer, v.exp.metadata, v.exp.statement];

  // Each asset from its public URL, exactly as a client fetches it, against the verified draft and GitHub's digest.
  // Only the fetch itself is retried (see publicRead); a response that arrives is checked once, so a retry can never
  // turn a size or hash mismatch into a pass.
  const got = {};
  let digests = 0;
  for (const n of names) {
    const url = `https://github.com/${repo}/releases/download/${encodeURIComponent(tag)}/${encodeURIComponent(n)}`;
    const r = await publicRead(io, () => io.download(url), d => {
      if (!d) return { retry: true, error: 'no response' };
      if (d.ok) return { value: d };
      return { retry: TRANSIENT_HTTP(d.status), error: `HTTP ${d.status}` };
    }, attempts, delayMs);
    if (r.error) { add('download-failed', `${n}: ${r.error}${r.tries > 1 ? ` (after ${r.tries} attempts)` : ''}`); continue; }
    const d = r.value;
    got[n] = d;
    const want = v.expected[n];
    if (d.size !== want.size) add('size-mismatch', `${n}: public download is ${d.size} bytes, verified draft ${want.size}`);
    if (d.sha256 !== want.sha256) add('digest-mismatch', `${n}: public sha256 differs from the verified draft`);
    const a = api.get(n);
    if (a && a.size !== d.size) add('size-mismatch', `${n}: public download is ${d.size} bytes, release API says ${a.size}`);
    if (a && a.digest) { digests++; if (a.digest !== `sha256:${d.sha256}`) add('digest-mismatch', `${n}: public sha256 differs from GitHub's digest`); }
  }

  // The publicly served installer against the verified draft, the public latest.yml and the public signed statement.
  const inst = got[v.exp.installer];
  if (inst) {
    const facts = { size: inst.size, sha512: inst.sha512 };
    if (facts.size !== v.installer.size || facts.sha512 !== v.installer.sha512) add('installer-changed', 'public installer size or sha512 differs from the verified draft');
    const recheck = [
      [v.exp.metadata, text => checkMetadata(config, version, v.exp, parseUpdateYml(text), facts)],
      [v.exp.statement, text => verifyStatement(text, v.publicKey, config, version, v.exp, facts, v.lastSequence)],
    ];
    for (const [n, check] of recheck) {
      const f = got[n];
      if (!f) continue; // already reported
      if (!f.body) { add('body-unavailable', `${n}: content not available for checking`); continue; }
      try { check(f.body.toString('utf8')); } catch (e) { add('installer-mismatch', `${n}: ${errText(e)}`); }
    }
  }
  // The feed can lag behind the release API: a read error or a stale first entry is re-read; the last answer counts.
  const feed = await publicRead(io, () => io.atomFirstTag(), f => (f === tag ? { value: f } : { retry: true, value: f }), attempts, delayMs);
  const after = feed.tries > 1 ? ` (after ${feed.tries} attempts)` : '';
  if (feed.thrown) add('atom-read', feed.error + after);
  else if (feed.value !== tag) add('atom-feed', `releases.atom first entry is ${feed.value}, expected ${tag}${after}`);
  return { problems: problems.map(p => redact(p)), digests, published: pub && { url: pub.html_url || null, publishedAt: pub.published_at || null } };
}

// After a failed verification: point `latest` back at the previous known-good release and read it back. With no such
// release, take the failed release out of /releases/latest by marking it a prerelease (immutable releases keep that flag
// editable) and read that back. The outcome comes from the read-back, never from the command's exit status alone.
// Neither action hides, deletes or edits the failed release or its assets.
export async function recoverLatest({ io, config, tag, previous }) {
  const steps = [], checks = [];
  if (previous) {
    let setError = null;
    try { await io.setLatest(previous.tag); steps.push(`asked GitHub to make ${previous.tag} the latest release`); }
    catch (e) { setError = errText(e); steps.push(`the command to make ${previous.tag} latest reported an error: ${setError}`); }
    try {
      const latest = await io.getLatest();
      if (!latest || latest.tag_name !== previous.tag) checks.push(`/releases/latest is ${latest ? latest.tag_name : 'missing'}, expected ${previous.tag}`);
    } catch (e) { checks.push(`could not read /releases/latest: ${errText(e)}`); }
    try {
      const rel = await io.getRelease(previous.tag);
      const want = expectedAssets(config, previous.version);
      const have = new Set((rel && Array.isArray(rel.assets) ? rel.assets : []).map(a => a.name));
      if (!rel || rel.draft !== false) checks.push(`${previous.tag} is not a published release`);
      else {
        if (rel.immutable !== true) checks.push(`${previous.tag} is not immutable`);
        if (rel.prerelease !== config.prerelease) checks.push(`${previous.tag} prerelease flag is ${rel.prerelease}`);
        for (const n of [want.installer, want.metadata, want.statement]) if (!have.has(n)) checks.push(`${previous.tag} lacks ${n}`);
      }
    } catch (e) { checks.push(`could not read ${previous.tag}: ${errText(e)}`); }
    // The read-back decides: a command error with a confirmed state is still restored (the error stays in `steps`).
    if (!checks.length) return { outcome: 'restored', target: previous.tag, detail: `${previous.tag} read back as the latest release${setError ? ' (the command reported an error, but the read-back confirms the change)' : ''}`, steps, checks };
    if (setError) return { outcome: 'restore-failed', target: previous.tag, detail: `${setError}; ${checks.join('; ')}`, steps, checks };
    return { outcome: 'restore-unverified', target: previous.tag, detail: checks.join('; '), steps, checks };
  }
  let setError = null;
  try { await io.setPrerelease(tag); steps.push(`no previous known-good release; asked GitHub to mark ${tag} as a prerelease`); }
  catch (e) { setError = errText(e); steps.push(`no previous known-good release; the command to mark ${tag} as a prerelease reported an error: ${setError}`); }
  try {
    const latest = await io.getLatest();
    if (latest) checks.push(`/releases/latest is ${latest.tag_name}, expected no latest release${latest.tag_name === tag ? '' : ' (that release is not a known-good release)'}`);
  } catch (e) { checks.push(`could not read /releases/latest: ${errText(e)}`); }
  try {
    const rel = await io.getRelease(tag);
    if (!rel || rel.prerelease !== true) checks.push(`${tag} prerelease flag reads back as ${rel && rel.prerelease}`);
  } catch (e) { checks.push(`could not read ${tag}: ${errText(e)}`); }
  if (!checks.length) return { outcome: 'withdrawn', target: null, detail: `${tag} is a prerelease and GitHub reports no latest release${setError ? ' (the command reported an error, but the read-back confirms the change)' : ''}`, steps, checks };
  if (setError) return { outcome: 'withdraw-failed', target: null, detail: `${setError}; ${checks.join('; ')}`, steps, checks };
  return { outcome: 'withdraw-unverified', target: null, detail: checks.join('; '), steps, checks };
}

// Where a ledger stands for one intended entry: 'absent' (no entry for the tag), 'match' (exactly one entry for the tag,
// equal to the intended entry in every field, nested failure record included) or 'conflict' (anything else; `differs`
// names the top-level fields that differ). Used to reconcile a write whose result was ambiguous.
export function ledgerEntryState(ledger, entry) {
  const canon = v => (v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => [k, canon(v[k])])) : Array.isArray(v) ? v.map(canon) : v);
  const found = ledger.releases.filter(r => r.tag === entry.tag);
  if (!found.length) return { state: 'absent', differs: [] };
  if (found.length > 1) return { state: 'conflict', differs: ['duplicate entries'] };
  const have = canon(found[0]), want = canon(entry);
  const differs = [...new Set([...Object.keys(have), ...Object.keys(want)])].filter(k => JSON.stringify(have[k]) !== JSON.stringify(want[k])).sort();
  return differs.length ? { state: 'conflict', differs, entry: found[0] } : { state: 'match', differs: [] };
}

// The ledger entry for a release whose post-publication verification failed. Small, fixed shape, no secrets.
export function failureEntry({ tag, version, v, published, problems, recovery, at }) {
  return {
    tag, version, sequence: v.statement.sequence, status: 'failed-verification',
    publishedAt: (published && published.publishedAt) || null, installerSha512: v.installer.sha512,
    failure: { at, checks: problems.slice(0, MAX_FAILURE_CHECKS).map(p => redact(p)), recovery: recovery.outcome, recoveryTarget: recovery.target },
  };
}

// Plain-language incident report for the job log, the workflow summary and the owner.
export function incidentReport({ repo, tag, published, problems, recovery, previous, latestBefore, ledgerError }) {
  const L = [];
  L.push(`POST-PUBLICATION VERIFICATION FAILED for ${tag}. This release is NOT healthy and must not be treated as a good release.`);
  L.push(`FAILED CHECKS (${problems.length}): ${problems.join(' | ')}`);
  L.push(`EXPOSED: ${tag} was made public${published && published.publishedAt ? ` at ${published.publishedAt}` : ''} and may have been served as the latest release before the checks finished. Restoring the pointer cannot undo a download a client already made.`);
  const r = recovery;
  for (const s of r.steps) L.push(`RECOVERY STEP: ${s}`);
  if (r.outcome === 'restored') L.push(`RESTORED: /releases/latest read back as ${previous.tag} (it was ${latestBefore || 'none'} before this publication); ${previous.tag} is still a published, immutable release with its three allowlisted assets. Its bytes were not re-hashed in this run.`);
  else if (r.outcome === 'withdrawn') L.push(`WITHDRAWN FROM LATEST: there is no previous known-good release, so nothing was restored. ${tag} was marked as a prerelease and GitHub now reports no latest release, so clients checking /releases/latest find no update.`);
  else L.push(`RECOVERY NOT CONFIRMED (${r.outcome}): ${r.detail}. Treat ${tag} as possibly still being served as the latest release.`);
  L.push(`STILL PUBLIC: the ${tag} release page, its three assets (direct download links keep working), the ${tag} tag and its releases.atom entry. The release is immutable: its assets cannot be edited, and nothing here deletes or hides it.`);
  // ledgerError: null, a string, or { kind: 'missing' | 'conflict' | 'unconfirmed', text } from the ledger write.
  const le = typeof ledgerError === 'string' ? { kind: 'missing', text: ledgerError } : ledgerError;
  if (le && le.kind === 'conflict') L.push(`LEDGER CONFLICT: ${le.text}. That entry was left unchanged and no second entry was added, so ${tag} is NOT recorded with this run's failed-verification details.`);
  else if (le && le.kind === 'unconfirmed') L.push(`LEDGER NOT CONFIRMED: ${le.text}. ${tag} may or may not be recorded as failed-verification. The next verification will refuse to run until the ledger has an entry for ${tag}.`);
  else if (le) L.push(`LEDGER NOT UPDATED: ${le.text}. ${tag} is NOT durably recorded as failed-verification. The next verification will refuse to run until the ledger has an entry for ${tag}.`);
  else L.push(`LEDGER: ${tag} recorded as failed-verification (recovery: ${r.outcome}) and read back. Its tag, version and sequence can never be reused, and retention will never delete it.`);
  const manual = [];
  if (r.outcome === 'restore-failed' || r.outcome === 'restore-unverified') manual.push(`set the latest release to ${previous.tag} yourself (gh release edit ${previous.tag} --repo ${repo} --latest) and confirm /releases/latest`);
  if (r.outcome === 'withdraw-failed' || r.outcome === 'withdraw-unverified') manual.push(`take ${tag} out of /releases/latest yourself (gh release edit ${tag} --repo ${repo} --prerelease, or delete the release) and confirm /releases/latest`);
  if (le && le.kind === 'conflict') manual.push(`correct the existing ledger entry for ${tag} by hand so it records this run's failed-verification (shown above); do not add a second entry`);
  else if (le && le.kind === 'unconfirmed') manual.push(`open ledger/releases.json: if it has no entry for ${tag}, add the failed-verification entry for ${tag}; if it has one that differs, correct it; never add a second entry`);
  else if (le) manual.push(`add the failed-verification entry for ${tag} to ledger/releases.json`);
  manual.push(`decide whether to leave ${tag} public or delete it (the tag name stays burned either way), then ship the fix as a new, higher version with a new tag`);
  L.push(`${manual.length > 1 ? 'MANUAL INTERVENTION REQUIRED' : 'NEXT STEP'}: ${manual.join('; then ')}. Retention was not run.`);
  return L;
}
