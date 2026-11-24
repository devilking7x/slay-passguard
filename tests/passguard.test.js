/**
 * Unit tests for PassGuard core logic (passguard.js).
 * Run: node --test tests/passguard.test.js
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../passguard.js');

test('module exposes the expected API', () => {
  assert.equal(typeof P.analyze, 'function');
  assert.equal(typeof P.generatePassword, 'function');
  assert.equal(typeof P.generatePassphrase, 'function');
  assert.equal(typeof P.formatDuration, 'function');
  assert.ok(P.commonPasswordCount >= 150, 'common list should be sizeable');
  assert.ok(P.wordlistSize >= 200, 'wordlist should be sizeable');
});

test('empty password scores 0 and asks for input', () => {
  const r = P.analyze('');
  assert.equal(r.score, 0);
  assert.equal(r.band.label, 'Very Weak');
  assert.equal(r.findings[0].code, 'empty');
});

test('the most common passwords score 5 or less', () => {
  for (const pw of ['password', '123456', 'qwerty', 'letmein', 'dragon', '123456789', '111111', 'admin']) {
    const r = P.analyze(pw);
    assert.ok(r.score <= 5, `${pw} scored ${r.score}`);
    assert.ok(r.findings.some((f) => f.code === 'commonExact'), `${pw} missing commonExact`);
    assert.equal(r.effectiveEntropy <= 8, true);
  }
});

test('leet-speak variants of common passwords are caught', () => {
  assert.ok(P.analyze('P@ssw0rd').findings.some((f) => f.code === 'commonExact'));
  assert.ok(P.analyze('p4ssw0rd').findings.some((f) => f.code === 'commonExact'));
  assert.ok(P.analyze('qwerty123').findings.some((f) => f.code === 'commonExact'));
});

test('keyboard walks are detected', () => {
  assert.ok(P.analyze('qwerty99!').findings.some((f) => f.code === 'keyboard'));
  assert.ok(P.analyze('ZxCvBnM123!').findings.some((f) => f.code === 'keyboard'));
  assert.ok(P.analyze('1qaz2wsx!').findings.some((f) => f.code === 'keyboard'));
});

test('sequences, repeats and years are detected', () => {
  assert.ok(P.analyze('abcXYZ99!').findings.some((f) => f.code === 'sequence'));
  assert.ok(P.analyze('hello99999!').findings.some((f) => f.code === 'repeatRun'));
  assert.ok(P.analyze('summer1998!').findings.some((f) => f.code === 'year'));
  assert.ok(P.analyze('abcabcabcabc').findings.some((f) => f.code === 'repeatUnit'));
});

test('a password containing a common password is flagged, not passed', () => {
  const r = P.analyze('sachin123');
  assert.ok(r.findings.some((f) => f.code === 'commonPart'));
  assert.ok(r.score < 40, `sachin123 scored ${r.score}`);
});

test('a random 16-char mixed password scores Very Strong', () => {
  const r = P.analyze('J7#kq9!Zx2$mQ8w');
  assert.equal(r.band.label, 'Very Strong');
  assert.ok(r.score >= 90);
  assert.equal(r.findings.length, 0);
  assert.ok(r.entropy > 90);
});

test('entropy maths: length x log2(pool)', () => {
  // 8 lowercase letters: 8 * log2(26) = 37.6
  assert.equal(P.analyze('abcdefgh').entropy, 37.6);
  // 8 digits: 8 * log2(10) = 26.6
  assert.equal(P.analyze('48291735').entropy, 26.6);
  // 4 mixed classes, 8 chars: 8 * log2(94) = 52.4
  assert.equal(P.analyze('aB3!xY9#').entropy, 52.4);
});

test('short passwords are capped even with mixed characters', () => {
  const r = P.analyze('aB3!xY');
  assert.ok(r.score <= 25, `6-char mixed scored ${r.score}`);
  assert.ok(r.findings.some((f) => f.code === 'tooShort'));
});

test('n-gram model: common passwords look predictable, random ones do not', () => {
  const common = P.ngramPredictability('password');
  const random = P.ngramPredictability('J7#kq9!Zx2$mQ8w');
  assert.ok(common.score >= 0.8, `password ngram ${common.score}`);
  assert.ok(random.score <= 0.3, `random ngram ${random.score}`);
  assert.ok(common.logProb > random.logProb);
});

test('crack-time estimates are ordered and labelled honestly', () => {
  const weak = P.analyze('password');
  const strong = P.analyze('J7#kq9!Zx2$mQ8w');
  assert.equal(weak.crackTime.offline, 'less than a second');
  assert.match(strong.crackTime.offline, /billion years/);
  // Offline (GPU) is always faster than throttled online for the same password.
  assert.notEqual(weak.crackTime.online, weak.crackTime.offline);
});

test('formatDuration handles the full range', () => {
  assert.equal(P.formatDuration(0.5), 'less than a second');
  assert.equal(P.formatDuration(45), '45 seconds');
  assert.equal(P.formatDuration(3600), '1 hour');
  assert.equal(P.formatDuration(86400 * 40), '40 days');
  assert.equal(P.formatDuration(86400 * 365.25 * 5), '5 years');
  assert.equal(P.formatDuration(Infinity), 'more than a billion years');
  assert.match(P.formatDuration(86400 * 365.25 * 5000000), /million years/);
});

test('generated passwords meet the requested spec', () => {
  for (let i = 0; i < 20; i++) {
    const pw = P.generatePassword({ length: 16 });
    assert.equal(pw.length, 16);
    assert.match(pw, /[a-z]/);
    assert.match(pw, /[A-Z]/);
    assert.match(pw, /[0-9]/);
    assert.match(pw, /[^a-zA-Z0-9]/);
    assert.ok(P.analyze(pw).score >= 90, `generated ${pw} scored ${P.analyze(pw).score}`);
  }
  const noSymbols = P.generatePassword({ length: 12, symbols: false });
  assert.equal(noSymbols.length, 12);
  assert.doesNotMatch(noSymbols, /[^a-zA-Z0-9]/);
});

test('generated passwords are not all the same', () => {
  const set = new Set();
  for (let i = 0; i < 50; i++) set.add(P.generatePassword({ length: 16 }));
  assert.equal(set.size, 50);
});

test('generated passphrases use the wordlist and report honest bits', () => {
  const r = P.generatePassphrase(5);
  assert.equal(r.words.length, 5);
  assert.equal(r.passphrase, r.words.join('-'));
  assert.ok(r.bits > 30 && r.bits < 60, `bits ${r.bits}`);
  assert.equal(r.wordlistSize, P.wordlistSize);
  const again = P.generatePassphrase(5);
  assert.notEqual(r.passphrase, again.passphrase);
});

test('advice is present in English and Hindi', () => {
  const weak = P.analyze('password');
  assert.ok(weak.advice.length >= 1);
  for (const a of weak.advice) {
    assert.ok(a.en && a.en.length > 10, 'English advice missing');
    assert.ok(a.hi && a.hi.length > 5, 'Hindi advice missing');
  }
  const strong = P.analyze('J7#kq9!Zx2$mQ8w');
  assert.ok(strong.advice.length >= 1);
});

test('band boundaries are consistent with the score', () => {
  const cases = [
    ['password', 'Very Weak'],
    ['sachin123', 'Weak'],
    ['Tr0ub4dor&3', 'Very Strong'],
    ['J7#kq9!Zx2$mQ8w', 'Very Strong']
  ];
  for (const [pw, band] of cases) {
    assert.equal(P.analyze(pw).band.label, band, `${pw}`);
  }
});
