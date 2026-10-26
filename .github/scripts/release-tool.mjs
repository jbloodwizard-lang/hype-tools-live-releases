#!/usr/bin/env node
// Release manager for one HYPE TOOLS release-only repository.
// Usage: node release-tool.mjs <verify|publish|retention|gate-check> --tag vX.Y.Z [--dry-run]
// publish: verifies the draft, publishes it, then verifies the published release from its public URLs. If any
// post-publication check fails, the release is recorded as failed-verification, `latest` is moved back to the previous
// known-good release (or, with none, the failed release is marked prerelease to take it out of `latest`), the result is
// read back, and the job fails with a report of what is still public and what needs a person.
// Needs only: node, the gh CLI, 7z (7-Zip, for installer inspection) and the job's GITHUB_TOKEN (as GH_TOKEN).
// No third-party packages.
import { spawn, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ReleaseError, fail, validateConfig, versionFromTag, checkAssetAllowlist, parseUpdateYml, checkMetadata,
  verifyStatement, validateLedger, lastPublished, planRetention, semverCmp, unrecordedReleases, previousGood, ledgerEntryState,
  verifyPublication, recoverLatest, failureEntry, incidentReport, redact, MAX_SMALL_FILE_BYTES,
} from './lib.mjs';
import { inspectInstaller } from './installer-inspection.mjs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
const readJson = f => JSON.parse(fs.readFileSync(path.join(ROOT, f), 'utf8'));
const args = process.argv.slice(2);
const cmd = args[0];
const opt = n => { const i = args.indexOf('--' + n); return i < 0 ? null : args[i + 1]; };
const DRY = args.includes('--dry-run');
const log = (...a) => console.log(...a);
const summary = [];
const note = (...a) => { const l = a.join(' '); summary.push(l); log(l); };

function gh(argv, { input } = {}) {
  return execFileSync('gh', argv, { encoding: 'utf8', input, maxBuffer: 64 * 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'] });
}
const ghJson = argv => JSON.parse(gh(argv));
const ghErr = e => redact(e && (e.stderr || e.message) || e, 200);
function listReleases(repo) {
  const all = [];
  for (let page = 1; page < 20; page++) {
    const part = ghJson(['api', `repos/${repo}/releases?per_page=100&page=${page}`]);
    all.push(...part);
    if (part.length < 100) break;
  }
  return all;
}
function downloadAsset(repo, id, dest) {
  return new Promise((resolve, reject) => {
    const p = spawn('gh', ['api', '-H', 'Accept: application/octet-stream', `repos/${repo}/releases/assets/${id}`], { stdio: ['ignore', 'pipe', 'pipe'] });
    const out = fs.createWriteStream(dest), s256 = crypto.createHash('sha256'), s512 = crypto.createHash('sha512');
    let size = 0, err = '';
    p.stdout.on('data', d => { size += d.length; s256.update(d); s512.update(d); out.write(d); });
    p.stderr.on('data', d => { err += d; });
    p.on('close', code => out.end(() => code === 0 ? resolve({ size, sha256: s256.digest('hex'), sha512: s512.digest('base64') }) : reject(new ReleaseError('download-failed', `asset ${id}: ${err.slice(0, 200)}`))));
  });
}

// Plain HTTPS read of a public release URL, as a client makes it: no token, redirects followed. Hashes while streaming;
// keeps the body only for small files (metadata and statement), never for the installer.
async function publicDownload(url) {
  const res = await fetch(url, { redirect: 'follow', signal: AbortSignal.timeout(30 * 60 * 1000) });
  if (!res.ok || !res.body) { await res.body?.cancel(); return { ok: false, status: res.status }; }
  const s256 = crypto.createHash('sha256'), s512 = crypto.createHash('sha512'), keep = [];
  let size = 0;
  for await (const chunk of res.body) {
    size += chunk.length; s256.update(chunk); s512.update(chunk);
    if (size <= MAX_SMALL_FILE_BYTES) keep.push(Buffer.from(chunk));
  }
  return { ok: true, status: res.status, size, sha256: s256.digest('hex'), sha512: s512.digest('base64'), body: size <= MAX_SMALL_FILE_BYTES ? Buffer.concat(keep) : null };
}

// The real GitHub side of the post-publication checks and recovery (see the io contract in lib.mjs).
function realIo(repo) {
  return {
    getRelease: async tag => ghJson(['api', `repos/${repo}/releases/tags/${encodeURIComponent(tag)}`]),
    getLatest: async () => {
      try { return ghJson(['api', `repos/${repo}/releases/latest`]); }
      catch (e) { if (/HTTP 404/.test(String(e.stderr || ''))) return null; throw e; }
    },
    download: publicDownload,
    atomFirstTag: async () => {
      const res = await fetch(`https://github.com/${repo}/releases.atom`, { signal: AbortSignal.timeout(60 * 1000) });
      if (!res.ok) throw new ReleaseError('atom-read', `releases.atom HTTP ${res.status}`);
      const first = /<entry>[\s\S]*?releases\/tag\/([^"]+)"/.exec(await res.text());
      return first ? decodeURIComponent(first[1]) : null;
    },
    setLatest: async tag => { gh(['release', 'edit', tag, '--repo', repo, '--latest']); },
    setPrerelease: async tag => { gh(['release', 'edit', tag, '--repo', repo, '--prerelease']); },
    sleep: ms => new Promise(r => setTimeout(r, ms)),
  };
}

function context() {
  const config = validateConfig(readJson('release-config.json'));
  const repo = process.env.GITHUB_REPOSITORY;
  if (repo !== config.repo) fail('wrong-repository', `this configuration is for ${config.repo}, running in ${repo}`);
  const ledger = validateLedger(readJson('ledger/releases.json'));
  const tag = opt('tag');
  if (!tag) fail('usage', '--tag is required');
  return { config, repo, ledger, tag, version: versionFromTag(config, tag) };
}

async function verifyDraft(ctx) {
  const { config, repo, tag, version, ledger } = ctx;
  const releases = listReleases(repo);
  const unrecorded = unrecordedReleases(config, ledger, releases);
  if (unrecorded.length) fail('unrecorded-release', `published releases with no ledger entry: ${unrecorded.join(', ')}. A previous publication did not finish recording; add their ledger entries (published or failed-verification) before publishing again`);
  const matches = releases.filter(r => r.tag_name === tag);
  if (matches.length !== 1) fail('release-lookup', `expected exactly one release for ${tag}, found ${matches.length}`);
  const rel = matches[0];
  if (!rel.draft) fail('not-draft', `${tag} is already published; only drafts can be verified for publication`);
  if (!Array.isArray(rel.assets)) fail('release-lookup', `${tag} has no asset list`);
  if (rel.prerelease !== config.prerelease) fail('prerelease-flag', `prerelease must be ${config.prerelease}`);
  const def = ghJson(['api', `repos/${repo}`]).default_branch;
  if (rel.target_commitish !== def) fail('bad-target', `release target must be ${def}, got ${rel.target_commitish}`);
  if (ledger.releases.some(r => r.tag === tag)) fail('tag-reused', `${tag} is already in the ledger; tag names are never reused`);
  const exp = checkAssetAllowlist(config, version, rel.assets);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hype-release-'));
  const facts = {}, expected = {};
  for (const a of rel.assets) {
    const dest = path.join(dir, a.name);
    const f = await downloadAsset(repo, a.id, dest);
    if (f.size !== a.size) fail('asset-size-mismatch', `${a.name}: downloaded ${f.size}, API says ${a.size}`);
    if (a.digest && a.digest !== `sha256:${f.sha256}`) fail('asset-digest-mismatch', a.name);
    facts[a.name] = { ...f, id: a.id, updated_at: a.updated_at };
    expected[a.name] = { size: f.size, sha256: f.sha256 };
  }
  const yml = parseUpdateYml(fs.readFileSync(path.join(dir, exp.metadata), 'utf8'));
  checkMetadata(config, version, exp, yml, facts[exp.installer]);
  // Open the installer that was just hashed: its packaged identity must match this channel and version, and an updater
  // test-fixture build is refused whatever the file is called.
  const inspected = inspectInstaller(path.join(dir, exp.installer), config, version, { expectedSha512: facts[exp.installer].sha512 });
  const keyFile = path.join(ROOT, config.publicKeyFile);
  const publicKey = fs.existsSync(keyFile) ? fs.readFileSync(keyFile, 'utf8').trim() : '';
  const last = lastPublished(ledger);
  const stmt = verifyStatement(fs.readFileSync(path.join(dir, exp.statement), 'utf8'), publicKey, config, version, exp, facts[exp.installer], last.sequence);
  if (semverCmp(version, last.version) <= 0) fail('version-not-newer', `${version} is not newer than the last published ${last.version}`);
  fs.rmSync(dir, { recursive: true, force: true });
  const snapshot = rel.assets.map(a => ({ id: a.id, name: a.name, size: a.size, updated_at: a.updated_at })).sort((x, y) => x.id - y.id);
  note(`verified draft ${tag}: ${rel.assets.length} allowlisted assets, installer ${facts[exp.installer].size} bytes (packaged ${inspected.name} ${inspected.version}, not a test build), statement sequence ${stmt.sequence}`);
  const installer = { size: facts[exp.installer].size, sha512: facts[exp.installer].sha512 };
  return { release: rel, snapshot, statement: stmt, installer, installerSha512: installer.sha512, exp, expected, lastSequence: last.sequence, publicKey };
}

function gateCheck(ctx) {
  const { config, repo } = ctx;
  if (!config.approvalEnvironment) { note('gate-check: no approval environment required for this channel'); return; }
  let env;
  try { env = ghJson(['api', `repos/${repo}/environments/${config.approvalEnvironment}`]); }
  catch (e) { fail('gate-unverifiable', `cannot read environment ${config.approvalEnvironment}: ${String(e.stderr || e.message).slice(0, 160)}`); }
  const rule = (env.protection_rules || []).find(r => r.type === 'required_reviewers');
  if (!rule || !(rule.reviewers || []).length) fail('gate-missing', `environment ${config.approvalEnvironment} has no required reviewers; LIVE publication is blocked`);
  note(`gate-check: environment ${config.approvalEnvironment} requires ${rule.reviewers.length} reviewer(s)`);
}

function readLedger(repo) {
  const cur = ghJson(['api', `repos/${repo}/contents/ledger/releases.json`]);
  return { sha: cur.sha, ledger: validateLedger(JSON.parse(Buffer.from(cur.content, 'base64').toString('utf8'))) };
}
// Used by retention for idempotent status changes. Each attempt re-reads the ledger; if the change is already there (for
// example a write that GitHub committed but answered with an error), nothing is written again.
function putLedger(repo, mutate) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const { sha, ledger } = readLedger(repo);
    const before = JSON.stringify(ledger);
    mutate(ledger);
    validateLedger(ledger);
    if (JSON.stringify(ledger) === before) return ledger;
    const body = { message: 'Update release ledger', content: Buffer.from(JSON.stringify(ledger, null, 2) + '\n').toString('base64'), sha };
    try { gh(['api', '-X', 'PUT', `repos/${repo}/contents/ledger/releases.json`, '--input', '-'], { input: JSON.stringify(body) }); return ledger; }
    catch (e) { if (attempt === 2) throw e; }
  }
}
// Adds one new ledger entry and confirms it from the ledger itself. Before every write and after every write error, the
// current ledger is read and compared with the whole intended entry (ledgerEntryState), so a write that GitHub committed
// but answered with an error is confirmed instead of repeated, and an entry is never duplicated or overwritten. At most 3
// writes, each after a fresh read (as before). Never throws: returns null when the exact entry is confirmed, otherwise
// { kind: 'missing' | 'conflict' | 'unconfirmed', text } so the caller can say plainly what is and is not recorded.
function recordLedger(repo, entry) {
  const errors = [];
  const confirmed = () => {
    if (errors.length) note(`ledger write for ${entry.tag}: the write command reported an error (${errors.join('; ')}), but the read-back shows the exact intended entry`);
    return null;
  };
  const conflict = s => ({ kind: 'conflict', text: `the ledger already has a different entry for ${entry.tag} (differs in: ${s.differs.join(', ')})${errors.length ? `; the write command had reported: ${errors.at(-1)}` : ''}` });
  const reconcile = () => {
    try { return ledgerEntryState(readLedger(repo).ledger, entry); }
    catch (e) { return { state: 'unreadable', error: ghErr(e) }; }
  };
  for (let attempt = 0; attempt < 3; attempt++) {
    let cur;
    try { cur = readLedger(repo); }
    catch (e) {
      const text = `ledger for ${entry.tag} could not be read (${ghErr(e)})`;
      return errors.length ? { kind: 'unconfirmed', text: `the write for ${entry.tag} could not be confirmed: the command reported ${errors.at(-1)} and the ${text}` } : { kind: 'missing', text };
    }
    const s = ledgerEntryState(cur.ledger, entry);
    if (s.state === 'match') return confirmed();
    if (s.state === 'conflict') return conflict(s);
    const next = { ...cur.ledger, releases: [...cur.ledger.releases, entry] };
    try { validateLedger(next); } catch (e) { return { kind: 'missing', text: `ledger entry for ${entry.tag} is invalid: ${e.message}` }; }
    const body = { message: 'Update release ledger', content: Buffer.from(JSON.stringify(next, null, 2) + '\n').toString('base64'), sha: cur.sha };
    try { gh(['api', '-X', 'PUT', `repos/${repo}/contents/ledger/releases.json`, '--input', '-'], { input: JSON.stringify(body) }); }
    catch (e) { errors.push(ghErr(e)); continue; } // the next round reads the ledger first: the write may have been committed
    const back = reconcile();
    if (back.state === 'match') return confirmed();
    if (back.state === 'conflict') return conflict(back);
    if (back.state === 'unreadable') return { kind: 'unconfirmed', text: `the write for ${entry.tag} was accepted but could not be confirmed: the ledger read-back failed (${back.error})` };
    return { kind: 'missing', text: `ledger read-back shows no entry for ${entry.tag}, expected ${entry.status}` };
  }
  // Every write reported an error: one last read decides whether any of them was committed.
  const last = reconcile();
  if (last.state === 'match') return confirmed();
  if (last.state === 'conflict') return conflict(last);
  if (last.state === 'unreadable') return { kind: 'unconfirmed', text: `the write for ${entry.tag} could not be confirmed: the command reported ${errors.at(-1)} and the ledger read-back failed (${last.error})` };
  return { kind: 'missing', text: `ledger write for ${entry.tag} failed: ${errors.at(-1)}` };
}

async function publish(ctx) {
  const { config, repo, tag, version } = ctx;
  gateCheck(ctx);
  const v = await verifyDraft(ctx);
  const io = realIo(repo);
  const releases = listReleases(repo);
  const previous = previousGood(ctx.ledger, releases, v.statement.sequence);
  let latestBefore = null;
  try { const l = await io.getLatest(); latestBefore = l ? l.tag_name : null; } catch (e) { latestBefore = `unreadable (${ghErr(e)})`; }
  note(`if post-publication checks fail: ${previous ? `latest goes back to ${previous.tag}, the previous known-good release` : `no previous known-good release exists, so ${tag} would be marked as a prerelease to take it out of latest`} (latest now: ${latestBefore || 'none'})`);
  if (DRY) { note(`dry run: would publish ${tag} with --latest, verify the published release and then apply retention (keep ${config.retention})`); return; }
  const again = releases.find(r => r.tag_name === tag);
  if (!again || !Array.isArray(again.assets)) fail('release-lookup', `${tag} could not be read again before publishing`);
  const snap2 = again.assets.map(a => ({ id: a.id, name: a.name, size: a.size, updated_at: a.updated_at })).sort((x, y) => x.id - y.id);
  if (again.draft !== true || JSON.stringify(snap2) !== JSON.stringify(v.snapshot)) fail('draft-changed', 'draft changed after verification; aborting');
  let publishError = null;
  try { gh(['release', 'edit', tag, '--repo', repo, '--draft=false', '--latest']); }
  catch (e) { publishError = ghErr(e); }
  if (publishError) {
    let state = null;
    try { state = listReleases(repo).find(r => r.tag_name === tag) || null; } catch { /* unknown */ }
    if (state && state.draft === true) fail('publish-failed', `${publishError}; ${tag} is still a draft, so nothing was made public`);
    note(`publish command reported an error (${publishError}); ${tag} ${state ? 'is no longer a draft' : 'could not be read back'}, so it is treated as published and checked`);
  } else note(`published ${tag}`);

  let result;
  try { result = await verifyPublication({ io, config, repo, tag, version, v }); }
  catch (e) { result = { problems: [`verification-error: ${ghErr(e)}`], published: null, digests: 0 }; }
  const problems = [...(publishError ? [`publish-command: ${publishError}`] : []), ...result.problems];
  if (!problems.length) {
    const ledgerError = recordLedger(repo, { tag, version, sequence: v.statement.sequence, status: 'published', publishedAt: result.published.publishedAt, installerSha512: v.installer.sha512 });
    note(`post-publish checks passed: draft cleared, prerelease ${config.prerelease}, immutable, latest is ${tag}, asset set unchanged, all three assets downloaded publicly and matched size and sha256 (GitHub digest compared for ${result.digests}), installer size and sha512 matched latest.yml and the signed statement, releases.atom`);
    if (ledgerError) {
      const fix = { conflict: `correct the existing entry for ${tag} in ledger/releases.json by hand so it records this published release; do not add a second entry`,
        unconfirmed: `open ledger/releases.json: if it has no entry for ${tag}, add a published entry for it; if it has one that differs, correct it; never add a second entry`,
        missing: `add a published entry for it to ledger/releases.json by hand` }[ledgerError.kind];
      fail('ledger-write', `${ledgerError.text}. ${tag} is public and verified but NOT recorded${ledgerError.kind === 'unconfirmed' ? ' as far as this run can confirm' : ''}; ${fix}. Retention was not run`);
    }
    note(`ledger updated for ${tag} (published, read back)`);
    await retention(ctx);
    return;
  }
  const recovery = await recoverLatest({ io, config, tag, previous });
  const ledgerError = recordLedger(repo, failureEntry({ tag, version, v, published: result.published, problems, recovery, at: new Date().toISOString() }));
  for (const l of incidentReport({ repo, tag, published: result.published, problems, recovery, previous, latestBefore, ledgerError })) note(l);
  fail('post-publish-check', `${tag} failed post-publication verification (${problems.length} problem(s)); latest recovery: ${recovery.outcome}; ledger ${ledgerError ? 'NOT updated' : 'updated'}`);
}

async function retention(ctx) {
  const { config, repo } = ctx;
  const { ledger } = readLedger(repo);
  const plan = planRetention({ ledger, liveReleases: listReleases(repo), keep: config.retention });
  note(`retention plan: keep ${JSON.stringify(plan.keep)}, delete ${JSON.stringify(plan.delete)}, unowned (never touched) ${JSON.stringify(plan.unowned)}, owned but not immutable ${JSON.stringify(plan.notImmutableOwned)}, failed verification (never deleted here) ${JSON.stringify(plan.failedOwned)}`);
  if (DRY) return;
  for (const tag of plan.delete) {
    gh(['release', 'delete', tag, '--repo', repo, '--yes']);
    putLedger(repo, l => { l.releases.find(r => r.tag === tag).status = 'retired'; });
    note(`retired ${tag} (release deleted; tag kept; tag name stays unusable)`);
  }
}

try {
  const ctx = context();
  if (cmd === 'verify') { await verifyDraft(ctx); }
  else if (cmd === 'gate-check') gateCheck(ctx);
  else if (cmd === 'publish') await publish(ctx);
  else if (cmd === 'retention') await retention(ctx);
  else fail('usage', 'command must be verify, publish, retention or gate-check');
  note(`result: OK (${cmd}${DRY ? ', dry run' : ''})`);
} catch (e) {
  note(`result: FAILED [${e.code || 'error'}] ${e.message}`);
  process.exitCode = 1;
} finally {
  if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, '### release-tool\n\n' + summary.map(s => '- ' + s).join('\n') + '\n');
}
