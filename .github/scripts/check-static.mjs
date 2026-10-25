// Static policy checks for this release-only repository. Fails the job on any violation.
import fs from 'node:fs';
import path from 'node:path';
import { validateConfig, validateLedger } from './lib.mjs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..');
// Patterns are assembled from pieces so this file does not match itself.
const SECRET_PATTERNS = [new RegExp('-----BEGIN [A-Z ]*PRIV' + 'ATE KEY-----'), new RegExp('github' + '_pat_'), new RegExp('gh' + 'p_[A-Za-z0-9]{20}'), new RegExp('gh' + 's_[A-Za-z0-9]{20}')];
const errors = [];
const bad = m => errors.push(m);
const walk = d => fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.name === '.git' ? [] : e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);

const config = validateConfig(JSON.parse(fs.readFileSync(path.join(ROOT, 'release-config.json'), 'utf8')));
validateLedger(JSON.parse(fs.readFileSync(path.join(ROOT, 'ledger/releases.json'), 'utf8')));

const ALLOWED = [/^README\.md$/, /^release-config\.json$/, /^ledger\/releases\.json$/, /^keys\/update-public-key\.txt$/, /^\.github\/(scripts|workflows)\/[A-Za-z0-9._-]+$/];
for (const f of walk(ROOT)) {
  const rel = path.relative(ROOT, f).split(path.sep).join('/');
  if (!ALLOWED.some(r => r.test(rel))) bad(`file not on the repository allowlist: ${rel}`);
  const text = fs.readFileSync(f, 'utf8');
  if (SECRET_PATTERNS.some(r => r.test(text))) bad(`possible secret in ${rel}`);
  if (rel.startsWith('.github/workflows/')) {
    if (!/^permissions: \{\}$/m.test(text)) bad(`${rel}: top-level permissions must be {}`);
    if (/\$\{\{\s*secrets\./.test(text)) bad(`${rel}: workflows must not use secrets`);
    for (const m of text.matchAll(/^\s*-?\s*uses:\s*(\S+)/gm)) {
      if (!/^actions\/checkout@[0-9a-f]{40}$/.test(m[1])) bad(`${rel}: action ${m[1]} is not the pinned allowlisted checkout`);
    }
    if (/pull_request_target|workflow_run/.test(text)) bad(`${rel}: risky trigger`);
    if (/contents:\s*write/.test(text) && !/workflow_dispatch/.test(text)) bad(`${rel}: write permission without manual trigger`);
    if (config.channel === 'live' && rel.endsWith('verify-and-publish.yml') && !new RegExp(`environment: ${config.approvalEnvironment}`).test(text)) bad(`${rel}: publish job must use the ${config.approvalEnvironment} environment`);
    if (config.channel === 'beta' && /live-release/.test(text)) bad(`${rel}: BETA repository references the LIVE environment`);
  }
}
const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
if (!readme.includes(config.productName)) bad('README does not name the product channel');
if (errors.length) { console.error(errors.join('\n')); process.exit(1); }
console.log(`static checks passed for ${config.repo}`);
