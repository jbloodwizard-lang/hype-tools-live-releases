// TEST ONLY. Preloaded with `node --import` by release-tool.test.mjs: replaces fetch with public-download and
// releases.atom answers built from the fake gh state ($FAKE_GH_STATE), so nothing reaches the network. Any other URL
// throws. Also makes retry waits instant.
import fs from 'node:fs';

const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...rest) => realSetTimeout(fn, 0, ...rest);

globalThis.fetch = async url => {
  const st = JSON.parse(fs.readFileSync(process.env.FAKE_GH_STATE, 'utf8'));
  const faults = st.faults || {};
  const u = new URL(String(url));
  let m;
  if (u.hostname !== 'github.com') throw new Error(`fake fetch: refusing ${u.href}`);
  if ((m = /^\/[^/]+\/[^/]+\/releases\/download\/([^/]+)\/([^/]+)$/.exec(u.pathname))) {
    const tag = decodeURIComponent(m[1]), name = decodeURIComponent(m[2]);
    const r = st.releases.find(x => x.tag_name === tag && !x.draft);
    const as = r && r.assets.find(x => x.name === name);
    if (faults.publicStatus && faults.publicStatus[name]) return new Response('error', { status: faults.publicStatus[name] });
    if (faults.publicThrows === name) throw new TypeError('fetch failed: ECONNRESET');
    if (!as) return new Response('Not Found', { status: 404 });
    let body = as.contentFile ? fs.readFileSync(as.contentFile) : Buffer.from(as.content, 'base64');
    if (faults.publicContent && faults.publicContent[name]) body = Buffer.from(faults.publicContent[name], 'base64');
    return new Response(body, { status: 200 });
  }
  if (/^\/[^/]+\/[^/]+\/releases\.atom$/.test(u.pathname)) {
    if (faults.atomStatus) return new Response('error', { status: faults.atomStatus });
    const entries = st.releases.filter(r => !r.draft).sort((x, y) => (y.publishOrder || 0) - (x.publishOrder || 0))
      .map(r => `<entry><link rel="alternate" type="text/html" href="https://github.com${u.pathname.replace(/\.atom$/, '')}/tag/${encodeURIComponent(r.tag_name)}"/></entry>`);
    return new Response(`<?xml version="1.0"?><feed>${entries.join('')}</feed>`, { status: 200 });
  }
  throw new Error(`fake fetch: unhandled ${u.href}`);
};
