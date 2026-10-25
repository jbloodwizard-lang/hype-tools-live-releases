#!/usr/bin/env node
// TEST ONLY. A fake of the few gh CLI calls release-tool.mjs makes, for release-tool.test.mjs. It never contacts GitHub.
// State lives in the JSON file named by $FAKE_GH_STATE. `faults` in that state simulates partial or failed GitHub
// behavior; every mutating call is appended to `calls` so tests can prove that a dry run changed nothing.
import fs from 'node:fs';

const st = JSON.parse(fs.readFileSync(process.env.FAKE_GH_STATE, 'utf8'));
const faults = st.faults || {};
const save = () => fs.writeFileSync(process.env.FAKE_GH_STATE, JSON.stringify(st));
const a = process.argv.slice(2);
const out = o => { process.stdout.write(typeof o === 'string' ? o : JSON.stringify(o)); };
const die = (msg, code = 1) => { save(); process.stderr.write(msg + '\n'); process.exit(code); };
const count = k => { st.counters = st.counters || {}; st.counters[k] = (st.counters[k] || 0) + 1; return st.counters[k]; };
// A fault value of true always fires; a number N fires on the first N uses.
const fires = (k, value) => value === true || (typeof value === 'number' && count(k) <= value);
const pub = r => ({ ...r, assets: r.assets.map(({ content, contentFile, ...x }) => x) });
const find = tag => st.releases.find(r => r.tag_name === tag);
// GitHub's rule: the latest release is the one explicitly made latest, else the newest non-draft, non-prerelease one.
const recomputeLatest = () => {
  const cur = st.latest && find(st.latest);
  if (cur && !cur.draft && !cur.prerelease) return;
  const cands = st.releases.filter(r => !r.draft && !r.prerelease).sort((x, y) => (x.publishOrder || 0) - (y.publishOrder || 0));
  st.latest = cands.length ? cands.at(-1).tag_name : null;
};

if (a[0] === 'api') {
  const accept = a.includes('-H') && /octet-stream/.test(a[a.indexOf('-H') + 1]);
  const method = a.includes('-X') ? a[a.indexOf('-X') + 1] : 'GET';
  const url = a.find(x => /^repos\//.test(x));
  let m;
  if ((m = /^repos\/[^/]+\/[^/]+\/releases\/assets\/(\d+)$/.exec(url)) && accept) {
    const as = st.releases.flatMap(r => r.assets).find(x => x.id === Number(m[1]));
    if (!as) die('gh: Not Found (HTTP 404)');
    process.stdout.write(as.contentFile ? fs.readFileSync(as.contentFile) : Buffer.from(as.content, 'base64'));
  } else if (/\/releases\?per_page/.test(url)) {
    const n = count('list');
    if (faults.changeDraftOnList === n) { const d = st.releases.find(r => r.draft); d.assets[0].updated_at = 'changed-' + n; }
    save(); out(st.releases.map(pub));
  } else if ((m = /\/releases\/tags\/(.+)$/.exec(url))) {
    const tag = decodeURIComponent(m[1]);
    if (fires('releaseRead', faults.releaseReadFails)) die('gh: HTTP 502: Bad Gateway');
    const r = find(tag);
    if (!r || r.draft) die('gh: Not Found (HTTP 404)');
    const view = pub(r);
    if (faults.publishedNoAssets === tag) delete view.assets;
    if (faults.publishedDigest && faults.publishedDigest.tag === tag) view.assets.find(x => x.name === faults.publishedDigest.name).digest = 'sha256:' + '0'.repeat(64);
    save(); out(view);
  } else if (/\/releases\/latest$/.test(url)) {
    if (fires('latestRead', faults.latestReadFails) || (faults.latestReadFailsAfterRecovery && (st.calls || []).some(c => /--latest$|--prerelease$/.test(c) && !/--draft=false/.test(c)))) die('gh: HTTP 503: Service Unavailable');
    const r = st.latest && find(st.latest);
    if (!r) die('gh: Not Found (HTTP 404)');
    save(); out(pub(r));
  } else if (/\/environments\//.test(url)) { if (!st.env) die('gh: HTTP 403'); out(st.env); }
  else if (/\/contents\/ledger\/releases\.json$/.test(url)) {
    if (method === 'PUT') {
      st.ledgerPuts = (st.ledgerPuts || 0) + 1;
      if (fires('ledgerPut', faults.ledgerPutFails)) die('gh: HTTP 409: ledger/releases.json does not match sha');
      const body = JSON.parse(fs.readFileSync(0, 'utf8'));
      if (body.sha !== st.ledgerSha) die('gh: HTTP 409: sha mismatch');
      if (!faults.ledgerPutDropped) { st.ledger = Buffer.from(body.content, 'base64').toString('utf8'); st.ledgerSha = 's' + st.ledgerPuts; }
      save(); out({});
    } else out({ sha: st.ledgerSha, content: Buffer.from(st.ledger).toString('base64') });
  } else if (/^repos\/[^/]+\/[^/]+$/.test(url)) out({ default_branch: 'main' });
  else die('fake gh: unhandled api ' + url, 2);
} else if (a[0] === 'release' && a[1] === 'edit') {
  const tag = a[2], flags = a.slice(3).filter(x => x.startsWith('--') && x !== '--repo');
  st.calls = [...(st.calls || []), `release edit ${tag} ${flags.join(' ')}`];
  const r = find(tag);
  if (!r) die('gh: release not found');
  if (flags.includes('--draft=false')) {
    if (fires('publishBefore', faults.publishErrorBefore)) die('gh: HTTP 500: publish failed');
    r.draft = false; r.published_at = '2026-10-25T12:00:00Z'; r.publishOrder = Math.max(0, ...st.releases.map(x => x.publishOrder || 0)) + 1;
    r.immutable = faults.publishNotImmutable ? false : true;
    if (flags.includes('--latest') && !faults.publishSkipsLatest) st.latest = tag;
    recomputeLatest();
    if (faults.publishErrorAfter) die('gh: HTTP 502: Bad Gateway (after the change was applied)');
  } else if (flags.includes('--latest')) {
    if (fires('setLatest', faults.setLatestFails)) die('gh: HTTP 422: Validation Failed');
    if (!faults.setLatestNoop) st.latest = tag;
    if (faults.setLatestErrorAfter) die('gh: HTTP 502: Bad Gateway (after the change was applied)');
  } else if (flags.includes('--prerelease')) {
    if (fires('setPrerelease', faults.setPrereleaseFails)) die('gh: HTTP 422: Validation Failed');
    r.prerelease = true; recomputeLatest();
    if (faults.setPrereleaseErrorAfter) die('gh: HTTP 502: Bad Gateway (after the change was applied)');
  } else die('fake gh: unhandled edit ' + flags.join(' '), 2);
  save();
} else if (a[0] === 'release' && a[1] === 'delete') {
  st.calls = [...(st.calls || []), `release delete ${a[2]}`];
  const i = st.releases.findIndex(r => r.tag_name === a[2]);
  st.releases.splice(i, 1); st.deleted = [...(st.deleted || []), a[2]]; recomputeLatest(); save();
} else die('fake gh: unhandled ' + a.join(' '), 2);
