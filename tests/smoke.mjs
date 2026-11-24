/**
 * Playwright smoke test for the PassGuard live page.
 * Serves the project dir over local HTTP and drives the real page in
 * Chromium. Run: node tests/smoke.mjs
 * (Uses the locally installed Playwright Chromium; no network needed.)
 */
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
let chromium;
try {
  ({ chromium } = require('playwright'));
} catch {
  // Fall back to the Playwright copy already installed on this machine.
  ({ chromium } = require('/home/hatch/workspace/video-build/node_modules/playwright'));
}

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8123;
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };

const server = http.createServer((req, res) => {
  const urlPath = decodeURIComponent(req.url.split('?')[0]);
  const file = path.join(ROOT, urlPath === '/' ? 'index.html' : urlPath);
  if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    res.writeHead(404);
    res.end('not found');
    return;
  }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
});

const results = [];
function check(name, ok, extra = '') {
  results.push({ name, ok, extra });
  console.log(`${ok ? '✔' : '✖'} ${name}${extra ? ' — ' + extra : ''}`);
}

await new Promise((resolve) => server.listen(PORT, '127.0.0.1', resolve));

let browser;
try {
  browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });

  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'networkidle' });
  check('page title mentions PassGuard', (await page.title()).includes('PassGuard'), await page.title());

  // Weak password -> Very Weak, low score.
  await page.fill('#password', 'password');
  await page.waitForTimeout(200);
  const weakScore = parseInt(await page.textContent('#score-value'), 10);
  const weakBand = await page.textContent('#band-label');
  check('password -> Very Weak, score <= 5', weakBand.includes('Very Weak') && weakScore <= 5, `score=${weakScore} band=${weakBand}`);
  const weakFindings = await page.textContent('#findings');
  check('weak password shows findings', /common/i.test(weakFindings), weakFindings.slice(0, 80));

  // Strong password -> Very Strong.
  await page.fill('#password', 'J7#kq9!Zx2$mQ8w');
  await page.waitForTimeout(200);
  const strongScore = parseInt(await page.textContent('#score-value'), 10);
  const strongBand = await page.textContent('#band-label');
  check('random 16-char -> Very Strong, score >= 90', strongBand.includes('Very Strong') && strongScore >= 90, `score=${strongScore}`);
  const crack = await page.textContent('#crack-offline');
  check('crack time shown for strong password', /billion years/.test(crack), crack);

  // Example button fills the input.
  await page.click('.example[data-pw="sachin123"]');
  await page.waitForTimeout(200);
  check('example button fills password', (await page.inputValue('#password')) === 'sachin123');

  // Show/hide toggle.
  await page.click('#toggle-visibility');
  check('show toggle reveals password', (await page.getAttribute('#password', 'type')) === 'text');

  // Password generator produces a 16-char output.
  await page.click('#gen-password-btn');
  const genPw = await page.textContent('#gen-password-output');
  check('password generator outputs 16 chars', genPw.length === 16, genPw);

  // Passphrase generator produces hyphenated words + bits.
  await page.click('#gen-passphrase-btn');
  const phrase = await page.textContent('#gen-passphrase-output');
  const bits = await page.textContent('#phrase-bits');
  check('passphrase generator outputs 5 hyphenated words', phrase.split('-').length === 5, phrase);
  check('passphrase bits shown', /bits/.test(bits), bits);

  // Hindi toggle switches advice language.
  await page.fill('#password', 'password');
  await page.waitForTimeout(100);
  await page.click('#lang-toggle');
  await page.waitForTimeout(200);
  const adviceHi = await page.textContent('#advice');
  check('Hindi toggle switches advice to Hindi', /[\u0900-\u097F]/.test(adviceHi), adviceHi.slice(0, 60));

  check('no page errors', errors.length === 0, errors.join(' | ').slice(0, 300));

  await page.screenshot({ path: path.join(ROOT, 'tests', 'smoke-screenshot.png'), fullPage: true });
  console.log('screenshot: tests/smoke-screenshot.png');
} finally {
  if (browser) await browser.close();
  server.close();
}

const failed = results.filter((r) => !r.ok);
console.log(`\nSmoke: ${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length ? 1 : 0);
