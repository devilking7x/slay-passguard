/**
 * PassGuard — honest, client-side password strength analysis.
 *
 * Everything here is computed locally in the browser. No password is ever
 * sent anywhere, no breach database is consulted, and nothing is invented:
 *  - entropy is computed from the character classes actually present,
 *  - pattern checks run against a small built-in list of widely published
 *    top-passwords plus keyboard/sequence/date/repeat detection,
 *  - "predictability" comes from a tiny character trigram model trained on
 *    that same built-in list (a real statistical model, ~200 passwords —
 *    small on purpose, and labelled as such in the UI),
 *  - crack times are estimates under stated assumptions (online 100
 *    guesses/sec, offline 10 billion guesses/sec) and are labelled estimates.
 *
 * UMD: works as a plain <script> in the browser (window.PassGuard) and as
 * a CommonJS module under Node for tests.
 */
(function (global, factory) {
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = factory();
  } else {
    global.PassGuard = factory();
  }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var VERSION = '1.0.0';

  /* ------------------------------------------------------------------ */
  /* Data                                                                */
  /* ------------------------------------------------------------------ */

  // A small built-in sample of the world's most published top-passwords
  // (RockYou / SplashData style lists). This is NOT a breach database and
  // is never presented as one — it only catches the most guessable choices.
  var COMMON_PASSWORDS = [
    '123456', 'password', '123456789', '12345', '12345678', 'qwerty',
    '1234567', '111111', '1234567890', '123123', 'abc123', '1234',
    'password1', 'iloveyou', '1q2w3e4r', '000000', 'qwerty123', 'zaq12wsx',
    'dragon', 'master', 'monkey', 'letmein', 'sunshine', 'princess',
    'admin', 'welcome', 'football', 'charlie', 'aa123456', 'donald',
    '123321', '654321', '987654321', 'qazwsx', '123qwe', 'killer',
    'trustno1', 'jordan', 'superman', 'michael', 'jesus', 'passw0rd',
    'shadow', 'maggie', 'computer', 'michelle', 'jessica', 'pepper',
    '12345678910', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1qaz2wsx',
    'mickey', 'freedom', 'whatever', 'nicole', 'samantha', 'ashley',
    'bailey', 'pass123', 'pass1234', 'admin123', 'user123', 'test123',
    'hello123', 'welcome1', 'welcome123', 'login123', 'secret', 'pass',
    '123123123', '11111111', '00000000', '88888888', '666666', '121212',
    '7777777', '123456a', 'a123456', 'abc123456', 'abcd1234', 'qwertyui',
    'qaz123', 'wsx123', 'edc123', 'qwe123', 'qweasdzxc', 'poiuyt',
    'lkjhgfds', 'mnbvcxz', 'qazxsw', 'india123', 'cricket', 'sachin',
    'rahul123', 'amit123', 'rohit123', 'virat123', 'delhi123', 'mumbai123',
    'flower', 'hunter', 'buster', 'soccer', 'harley', 'batman',
    'andrew', 'tigger', 'sunshine1', 'jasmine', 'daniel', 'babygirl',
    'lovely', 'anthony', 'justin', 'pokemon', 'naruto', 'guitar',
    'cheese', 'cookie', 'summer', 'winter', 'autumn', 'spring',
    'liverpool', 'chelsea', 'arsenal', 'manutd', 'barcelona', 'madrid',
    'samsung', 'nokia', 'iphone', 'google', 'yahoo', 'hotmail',
    'qwerty12345', '12345qwert', 'asdf1234', 'zxcv1234', 'passw0rd123',
    'changeme', 'default', 'root123', 'toor123', 'god123', 'love123',
    'star123', 'moon123', 'king123', 'queen123', 'lucky123', 'money123',
    'hello', 'world', 'test', 'demo', 'guest', 'user', 'root', 'admin1',
    'passw0rd1', 'letmein123', 'dragon123', 'monkey123', 'shadow123',
    'master123', 'superman123', 'batman123', 'trustno1!', 'jordan23',
    'killer123', 'freedom123', 'computer123', 'michelle1', 'jessica1',
    'maggie123', 'snoopy', 'scooter', 'peanut', 'buster1', 'jasper',
    'george', 'thomas', 'charlie1', 'oliver', 'jack123', 'london123',
    'paris123', 'berlin123', 'tokyo123', 'moscow123', 'sydney123',
    'chocolate', 'coffee123', 'pizza123', 'burger', 'tiger123', 'lion123',
    'eagle123', 'falcon', 'panther', 'cobra123', 'python123', 'java123'
  ];
  var COMMON_SET = {};
  COMMON_PASSWORDS.forEach(function (p) { COMMON_SET[p] = true; });

  // Keyboard rows (QWERTY) + common diagonal walks, for walk detection.
  var KEYBOARD_ROWS = [
    'qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890',
    '1qaz', '2wsx', '3edc', '4rfv', '5tgb', '6yhn', '7ujm', '8ik', '9ol', '0p'
  ];

  // Wordlist for memorable passphrases (short everyday English words).
  // Deduplicated at load; strength = words * log2(list length).
  var WORDLIST = [
    'apple', 'river', 'tiger', 'mango', 'cloud', 'stone', 'music',
    'garden', 'candle', 'bridge', 'turtle', 'monkey', 'rocket', 'planet',
    'guitar', 'violin', 'pocket', 'window', 'bottle', 'hammer', 'feather',
    'rainbow', 'thunder', 'meadow', 'valley', 'forest', 'desert', 'ocean',
    'island', 'castle', 'dragon', 'wizard', 'pirate', 'sailor', 'farmer',
    'hunter', 'runner', 'dancer', 'singer', 'writer', 'painter', 'baker',
    'doctor', 'teacher', 'driver', 'jumper', 'climber', 'swimmer',
    'falcon', 'eagle', 'cobra', 'python', 'jaguar', 'panther', 'leopard',
    'wolf', 'bear', 'lion', 'horse', 'zebra', 'koala', 'panda', 'otter',
    'lemon', 'melon', 'berry', 'peach', 'grape', 'cherry', 'banana',
    'orange', 'papaya', 'guava', 'lychee', 'almond', 'walnut', 'cashew',
    'bread', 'honey', 'sugar', 'spice', 'pepper', 'ginger', 'mint',
    'coffee', 'cocoa', 'pizza', 'pasta', 'noodle', 'cheese', 'butter',
    'silver', 'golden', 'copper', 'marble', 'crystal', 'diamond', 'ruby',
    'pearl', 'coral', 'amber', 'jade', 'onyx', 'topaz', 'quartz',
    'spring', 'summer', 'autumn', 'winter', 'morning', 'evening',
    'midnight', 'sunset', 'sunrise', 'moonlight', 'starlight', 'comet',
    'meteor', 'nebula', 'galaxy', 'cosmos', 'orbit', 'lunar', 'solar',
    'meadow', 'prairie', 'canyon', 'glacier', 'volcano', 'lagoon',
    'harbour', 'beacon', 'lantern', 'compass', 'anchor', 'sailor',
    'voyage', 'journey', 'trail', 'pathway', 'crossing', 'summit',
    'harbor', 'island', 'peninsula', 'delta', 'fjord', 'oasis',
    'velvet', 'silk', 'cotton', 'linen', 'denim', 'canvas',
    'puzzle', 'riddle', 'mystery', 'secret', 'legend', 'mythic',
    'brave', 'bold', 'calm', 'swift', 'clever', 'gentle', 'happy',
    'jolly', 'lucky', 'merry', 'noble', 'proud', 'quiet', 'rapid',
    'sandy', 'shiny', 'silky', 'sunny', 'tasty', 'vivid', 'witty',
    'zesty', 'amber', 'azure', 'coral', 'crimson', 'emerald', 'ivory',
    'scarlet', 'violet', 'indigo', 'magenta', 'turquoise', 'lavender',
    'cricket', 'hockey', 'tennis', 'soccer', 'boxing', 'racing',
    'surfing', 'skiing', 'rowing', 'archery', 'fencing', 'bowling',
    'temple', 'mosque', 'palace', 'market', 'bazaar', 'street',
    'village', 'hamlet', 'meadow', 'orchard', 'vineyard', 'mill',
    'forge', 'kiln', 'loom', 'plow', 'sickle', 'scythe',
    'maple', 'cedar', 'birch', 'willow', 'poplar', 'alder',
    'acorn', 'walnut', 'chestnut', 'hazel', 'juniper', 'cypress',
    'falcon', 'heron', 'raven', 'sparrow', 'robin', 'wren',
    'badger', 'beaver', 'bison', 'camel', 'donkey', 'ferret',
    'goose', 'heron', 'ibis', 'kangaroo', 'lemur', 'moose',
    'otter', 'puma', 'quail', 'raccoon', 'seal', 'toucan',
    'viper', 'walrus', 'yak', 'zebra', 'orca', 'shark',
    'coral', 'kelp', 'pearl', 'shell', 'tide', 'wave',
    'flint', 'granite', 'basalt', 'slate', 'chalk', 'clay',
    'ember', 'flame', 'spark', 'blaze', 'torch', 'cinder',
    'frost', 'glacier', 'hail', 'snow', 'rain', 'storm',
    'breeze', 'gale', 'zephyr', 'mist', 'fog', 'dew',
    'atlas', 'orion', 'lyra', 'vega', 'altair', 'rigel',
    'sirius', 'polaris', 'capella', 'deneb', 'betelgeuse'
  ];
  // Deduplicate the wordlist (keeps the strength maths honest).
  var WORDS = [];
  var _seen = {};
  WORDLIST.forEach(function (w) {
    if (!_seen[w]) { _seen[w] = true; WORDS.push(w); }
  });

  /* Leet-speak normalisation, so p@ssw0rd is caught like password. */
  var LEET = { '@': 'a', '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '$': 's', '!': 'i' };
  function deleet(s) {
    return s.toLowerCase().split('').map(function (c) {
      return LEET[c] || c;
    }).join('');
  }

  /* ------------------------------------------------------------------ */
  /* Random helpers (crypto-backed, no Math.random for secrets)          */
  /* ------------------------------------------------------------------ */

  function cryptoObj() {
    if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
      return globalThis.crypto;
    }
    if (typeof global !== 'undefined' && global.crypto && global.crypto.getRandomValues) {
      return global.crypto;
    }
    return null;
  }

  // Uniform random integer in [0, max) without modulo bias.
  function randomInt(max) {
    var c = cryptoObj();
    if (c) {
      var range = 4294967296;
      var limit = range - (range % max);
      var buf = new Uint32Array(1);
      var v;
      do {
        c.getRandomValues(buf);
        v = buf[0];
      } while (v >= limit);
      return v % max;
    }
    // Node fallback (no browser crypto): require lazily so browsers never see it.
    if (typeof require === 'function') {
      return require('crypto').randomInt(max);
    }
    throw new Error('No secure random source available');
  }

  /* ------------------------------------------------------------------ */
  /* Trigram predictability model                                        */
  /*                                                                        */
  /* A tiny character trigram model trained on the built-in common-        */
  /* password list. It answers one question: "does this password look     */
  /* like the passwords everybody picks?" A password made of trigrams     */
  /* that are frequent in common passwords scores as MORE predictable.     */
  /* This is a real statistical model — but a deliberately small one,      */
  /* and the UI says so.                                                   */
  /* ------------------------------------------------------------------ */

  var _trigramCounts = null;
  var _trigramTotals = null;
  function trigramModel() {
    if (_trigramCounts) return;
    _trigramCounts = {};
    _trigramTotals = {};
    COMMON_PASSWORDS.forEach(function (pw) {
      var s = '^^' + pw.toLowerCase() + '$$';
      for (var i = 0; i < s.length - 2; i++) {
        var ctx = s.slice(i, i + 2);
        var ch = s[i + 2];
        if (!_trigramCounts[ctx]) _trigramCounts[ctx] = {};
        _trigramCounts[ctx][ch] = (_trigramCounts[ctx][ch] || 0) + 1;
        _trigramTotals[ctx] = (_trigramTotals[ctx] || 0) + 1;
      }
    });
  }

  // Average log10 probability of the password's trigrams (higher = more
  // like a common password = more predictable). Add-0.1 smoothing.
  function ngramLogProb(pw) {
    trigramModel();
    var s = '^^' + pw.toLowerCase() + '$$';
    if (s.length < 3) return -6;
    var sum = 0;
    var n = 0;
    for (var i = 0; i < s.length - 2; i++) {
      var ctx = s.slice(i, i + 2);
      var ch = s[i + 2];
      var counts = _trigramCounts[ctx] || {};
      var total = _trigramTotals[ctx] || 0;
      var p = ((counts[ch] || 0) + 0.1) / (total + 0.1 * 80);
      sum += Math.log10(p);
      n++;
    }
    return n === 0 ? -6 : sum / n;
  }

  // Map the average log-prob to a 0..1 predictability score.
  // Calibrated empirically: common passwords sit near -0.6, random
  // strings near -1.9 (the smoothing floor). 0 = looks random,
  // 1 = looks like a common password.
  function ngramPredictability(pw) {
    var lp = ngramLogProb(pw);
    var score = (lp + 1.95) / 1.45;
    if (score < 0) score = 0;
    if (score > 1) score = 1;
    return { logProb: Math.round(lp * 100) / 100, score: Math.round(score * 100) / 100 };
  }

  /* ------------------------------------------------------------------ */
  /* Pattern checks                                                      */
  /* ------------------------------------------------------------------ */

  function findKeyboardWalk(pw) {
    var low = pw.toLowerCase();
    for (var r = 0; r < KEYBOARD_ROWS.length; r++) {
      var row = KEYBOARD_ROWS[r];
      var rev = row.split('').reverse().join('');
      for (var len = 4; len <= row.length; len++) {
        for (var i = 0; i + len <= row.length; i++) {
          var sub = row.slice(i, i + len);
          if (low.indexOf(sub) !== -1) return sub;
          var subRev = rev.slice(i, i + len);
          if (low.indexOf(subRev) !== -1) return subRev;
        }
      }
    }
    return null;
  }

  function findSequence(pw) {
    var low = pw.toLowerCase();
    for (var i = 0; i + 2 < low.length; i++) {
      var a = low.charCodeAt(i), b = low.charCodeAt(i + 1), c = low.charCodeAt(i + 2);
      if ((b === a + 1 && c === b + 1) || (b === a - 1 && c === b - 1)) {
        return low.slice(i, i + 3);
      }
    }
    return null;
  }

  function findRepeatRun(pw) {
    var m = /(.)\1{2,}/.exec(pw);
    return m ? m[0] : null;
  }

  function findRepeatedUnit(pw) {
    // Password built by repeating a shorter chunk: "abcabc", "1212".
    for (var unitLen = 1; unitLen <= Math.floor(pw.length / 2); unitLen++) {
      if (pw.length % unitLen !== 0) continue;
      var unit = pw.slice(0, unitLen);
      var rebuilt = unit.repeat(pw.length / unitLen);
      if (rebuilt === pw && pw.length >= 4) return unit;
    }
    return null;
  }

  function findYear(pw) {
    var m = /(19\d\d|20\d\d)/.exec(pw);
    return m ? m[0] : null;
  }

  function containsCommon(pw) {
    var norm = deleet(pw);
    var found = null;
    COMMON_PASSWORDS.forEach(function (common) {
      if (common.length >= 4 && norm.indexOf(common) !== -1) {
        if (!found || common.length > found.length) found = common;
      }
    });
    return found;
  }

  /* ------------------------------------------------------------------ */
  /* Human time formatting                                               */
  /* ------------------------------------------------------------------ */

  function formatDuration(seconds) {
    function qty(n, unit) {
      return n + ' ' + unit + (n === 1 ? '' : 's');
    }
    if (!isFinite(seconds)) return 'more than a billion years';
    if (seconds < 1) return 'less than a second';
    if (seconds < 60) return qty(Math.round(seconds), 'second');
    var minutes = seconds / 60;
    if (minutes < 60) return qty(Math.round(minutes), 'minute');
    var hours = minutes / 60;
    if (hours < 24) return qty(Math.round(hours), 'hour');
    var days = hours / 24;
    if (days < 365) return qty(Math.round(days), 'day');
    var years = days / 365.25;
    if (years < 1000) return qty(Math.round(years), 'year');
    if (years < 1000000) return qty(Math.round(years / 1000), 'thousand year');
    if (years < 1000000000) return (years / 1000000).toFixed(1) + ' million years';
    return 'more than a billion years';
  }

  /* ------------------------------------------------------------------ */
  /* Advice (English + Hindi)                                            */
  /* ------------------------------------------------------------------ */

  var ADVICE = {
    tooShort: {
      en: 'Make it at least 12 characters — length is the single biggest factor.',
      hi: 'कम से कम 12 अक्षर का रखें — लंबाई ही सबसे बड़ा फैक्टर है।'
    },
    shortish: {
      en: 'Longer is stronger: aim for 16+ characters if you can remember it.',
      hi: 'लंबा पासवर्ड ज़्यादा मज़बूत होता है: हो सके तो 16+ अक्षर रखें।'
    },
    commonExact: {
      en: 'This is one of the most-used passwords in the world — attackers try it first. Never use it.',
      hi: 'यह दुनिया के सबसे ज़्यादा इस्तेमाल होने वाले पासवर्ड में से एक है — हमले में यह सबसे पहले try होता है। इसे कभी इस्तेमाल न करें।'
    },
    commonPart: {
      en: 'It contains a very common password. Change that part completely.',
      hi: 'इसमें एक बहुत आम पासवर्ड छिपा है। उस हिस्से को पूरी तरह बदलें।'
    },
    keyboard: {
      en: 'It follows a keyboard pattern. Avoid straight lines across the keyboard.',
      hi: 'यह keyboard pattern है। Keyboard पर सीधी line वाले pattern से बचें।'
    },
    sequence: {
      en: 'It contains a sequence like "abc" or "123". Mix things up instead.',
      hi: 'इसमें "abc" या "123" जैसा sequence है। इसके बजाय चीज़ें mix करें।'
    },
    repeatRun: {
      en: 'Repeated characters add almost no strength. Use varied characters.',
      hi: 'बार-बार वही अक्षर कोई मज़बूती नहीं देते। अलग-अलग अक्षर इस्तेमाल करें।'
    },
    repeatUnit: {
      en: 'Repeating the same chunk does not make it much stronger. Make each part different.',
      hi: 'एक ही टुकड़े को दोहराने से पासवर्ड ज़्यादा मज़बूत नहीं होता। हर हिस्सा अलग रखें।'
    },
    year: {
      en: 'Years (birth years, etc.) are easy to guess. Leave dates out.',
      hi: 'साल (जन्म साल आदि) आसानी से guess हो जाता है। Date न डालें।'
    },
    singleClass: {
      en: 'Use a mix: small + capital letters, numbers and symbols.',
      hi: 'Mix इस्तेमाल करें: छोटे + बड़े अक्षर, number और symbol।'
    },
    lowUnique: {
      en: 'Too few different characters. Variety matters as much as length.',
      hi: 'बहुत कम अलग अक्षर हैं। लंबाई जितनी ही variety भी ज़रूरी है।'
    },
    predictable: {
      en: 'It looks like passwords people commonly pick. Try random words or a generated password.',
      hi: 'यह आम तौर पर चुने गए पासवर्ड जैसा लगता है। Random शब्द या generated password try करें।'
    },
    genericStrong: {
      en: 'Strong! Still: use a different password for every site, and turn on 2-step verification.',
      hi: 'मज़बूत है! फिर भी: हर site के लिए अलग पासवर्ड रखें और 2-step verification चालू करें।'
    },
    genericManager: {
      en: 'A password manager can remember a long random password for you.',
      hi: 'Password manager आपके लिए लंबा random password याद रख सकता है।'
    }
  };

  /* ------------------------------------------------------------------ */
  /* Main analysis                                                       */
  /* ------------------------------------------------------------------ */

  var BANDS = [
    { min: 0, max: 19, label: 'Very Weak', hi: 'बहुत कमज़ोर' },
    { min: 20, max: 39, label: 'Weak', hi: 'कमज़ोर' },
    { min: 40, max: 59, label: 'Fair', hi: 'ठीक-ठाक' },
    { min: 60, max: 79, label: 'Strong', hi: 'मज़बूत' },
    { min: 80, max: 100, label: 'Very Strong', hi: 'बहुत मज़बूत' }
  ];

  function analyze(password) {
    if (typeof password !== 'string') password = String(password == null ? '' : password);
    var pw = password;
    var len = pw.length;

    var hasLower = /[a-z]/.test(pw);
    var hasUpper = /[A-Z]/.test(pw);
    var hasDigit = /[0-9]/.test(pw);
    var hasSymbol = /[^a-zA-Z0-9]/.test(pw);
    var hasNonAscii = /[^\x00-\x7F]/.test(pw);
    var classes = (hasLower ? 1 : 0) + (hasUpper ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSymbol ? 1 : 0);

    var pool = 0;
    if (hasLower) pool += 26;
    if (hasUpper) pool += 26;
    if (hasDigit) pool += 10;
    if (hasSymbol) pool += 32;
    if (hasNonAscii) pool += 500;
    var entropy = len === 0 ? 0 : len * (Math.log(pool) / Math.log(2));
    entropy = Math.round(entropy * 10) / 10;

    var findings = [];
    var adviceKeys = [];
    var penalty = 0;

    if (len === 0) {
      return {
        passwordLength: 0, entropy: 0, effectiveEntropy: 0, score: 0,
        band: BANDS[0], classes: 0, pool: 0, findings: [
          { code: 'empty', severity: 'info', en: 'Type a password to check it.', hi: 'Check करने के लिए password लिखें।' }
        ],
        positives: [], advice: [ADVICE.genericManager],
        crackTime: { online: '—', offline: '—' },
        ngram: { logProb: 0, score: 0, label: '—' },
        charset: { lower: false, upper: false, digit: false, symbol: false, nonAscii: false }
      };
    }

    var norm = deleet(pw);
    var exactCommon = !!(COMMON_SET[pw.toLowerCase()] || COMMON_SET[norm]);

    if (len < 8) {
      findings.push({ code: 'tooShort', severity: 'critical', en: 'Too short (' + len + ' characters).', hi: 'बहुत छोटा (' + len + ' अक्षर)।' });
      adviceKeys.push('tooShort');
      penalty += 12;
    } else if (len < 12) {
      findings.push({ code: 'shortish', severity: 'warning', en: 'Quite short (' + len + ' characters).', hi: 'काफ़ी छोटा (' + len + ' अक्षर)।' });
      adviceKeys.push('shortish');
      penalty += 4;
    }

    if (exactCommon) {
      findings.push({ code: 'commonExact', severity: 'critical', en: 'This is one of the most common passwords.', hi: 'यह सबसे आम passwords में से एक है।' });
      adviceKeys.push('commonExact');
    } else {
      var contained = containsCommon(pw);
      if (contained) {
        findings.push({ code: 'commonPart', severity: 'warning', en: 'Contains the common password "' + contained + '".', hi: 'इसमें आम password "' + contained + '" है।' });
        adviceKeys.push('commonPart');
        penalty += 12;
      }
    }

    var walk = findKeyboardWalk(pw);
    if (walk) {
      findings.push({ code: 'keyboard', severity: 'warning', en: 'Keyboard walk detected: "' + walk + '".', hi: 'Keyboard pattern मिला: "' + walk + '"।' });
      adviceKeys.push('keyboard');
      penalty += 10;
    }

    var seq = findSequence(pw);
    if (seq) {
      findings.push({ code: 'sequence', severity: 'warning', en: 'Sequence detected: "' + seq + '".', hi: 'Sequence मिला: "' + seq + '"।' });
      adviceKeys.push('sequence');
      penalty += 6;
    }

    var run = findRepeatRun(pw);
    if (run) {
      findings.push({ code: 'repeatRun', severity: 'warning', en: 'Repeated characters: "' + run + '".', hi: 'दोहराने वाले अक्षर: "' + run + '"।' });
      adviceKeys.push('repeatRun');
      penalty += 6;
    }

    var unit = findRepeatedUnit(pw);
    if (unit) {
      findings.push({ code: 'repeatUnit', severity: 'warning', en: 'Repeats the chunk "' + unit + '".', hi: 'टुकड़ा "' + unit + '" दोहराता है।' });
      adviceKeys.push('repeatUnit');
      penalty += 10;
    }

    var year = findYear(pw);
    if (year) {
      findings.push({ code: 'year', severity: 'warning', en: 'Contains the year ' + year + ' — years are easy to guess.', hi: 'इसमें साल ' + year + ' है — साल आसानी से guess होता है।' });
      adviceKeys.push('year');
      penalty += 8;
    }

    if (classes <= 1 && len >= 4) {
      findings.push({ code: 'singleClass', severity: 'warning', en: 'Uses only one kind of character.', hi: 'सिर्फ़ एक तरह के अक्षर इस्तेमाल हुए हैं।' });
      adviceKeys.push('singleClass');
      penalty += 4;
    }

    var uniqueCount = {};
    pw.split('').forEach(function (c) { uniqueCount[c] = true; });
    var unique = Object.keys(uniqueCount).length;
    if (len >= 6 && unique / len < 0.4) {
      findings.push({ code: 'lowUnique', severity: 'warning', en: 'Only ' + unique + ' different characters in ' + len + '.', hi: 'सिर्फ़ ' + unique + ' अलग अक्षर ' + len + ' में।' });
      adviceKeys.push('lowUnique');
      penalty += 6;
    }

    var ngram = ngramPredictability(pw);
    var ngramLabel = ngram.score >= 0.66 ? 'High' : ngram.score >= 0.33 ? 'Medium' : 'Low';
    if (ngram.score >= 0.66 && !exactCommon) {
      findings.push({ code: 'predictable', severity: 'warning', en: 'Looks like passwords people commonly pick (statistical model).', hi: 'आम तौर पर चुने गए passwords जैसा लगता है (statistical model)।' });
      adviceKeys.push('predictable');
      penalty += 8;
    }

    var effectiveEntropy = entropy - penalty;
    if (exactCommon) effectiveEntropy = Math.min(effectiveEntropy, 8);
    if (effectiveEntropy < 0) effectiveEntropy = 0;
    effectiveEntropy = Math.round(effectiveEntropy * 10) / 10;

    var score = Math.round(Math.min(100, (effectiveEntropy / 80) * 100));
    if (len < 8) score = Math.min(score, 25);
    if (exactCommon) score = Math.min(score, 5);

    var band = BANDS[0];
    BANDS.forEach(function (b) { if (score >= b.min && score <= b.max) band = b; });

    // Crack-time estimates (labelled estimates, stated assumptions).
    var avgGuesses = effectiveEntropy <= 0 ? 1 : Math.pow(2, effectiveEntropy - 1);
    var crackTime = {
      online: formatDuration(avgGuesses / 100),        // throttled login, 100 guesses/sec
      offline: formatDuration(avgGuesses / 10000000000) // fast hash on a GPU, 10 billion/sec
    };

    var positives = [];
    if (len >= 12) positives.push({ en: 'Good length (' + len + ' characters).', hi: 'अच्छी लंबाई (' + len + ' अक्षर)।' });
    if (classes === 4) positives.push({ en: 'Uses all four character types.', hi: 'चारों तरह के अक्षर इस्तेमाल हुए।' });
    if (findings.length === 0) positives.push({ en: 'No common patterns detected.', hi: 'कोई आम pattern नहीं मिला।' });
    if (entropy >= 60) positives.push({ en: 'High entropy (' + entropy + ' bits).', hi: 'High entropy (' + entropy + ' bits)।' });

    if (adviceKeys.length === 0) adviceKeys.push('genericStrong');
    if (score < 80) adviceKeys.push('genericManager');
    var advice = [];
    adviceKeys.slice(0, 5).forEach(function (k) { advice.push(ADVICE[k]); });

    return {
      passwordLength: len,
      entropy: entropy,
      effectiveEntropy: effectiveEntropy,
      score: score,
      band: band,
      classes: classes,
      pool: pool,
      findings: findings,
      positives: positives,
      advice: advice,
      crackTime: crackTime,
      ngram: { logProb: ngram.logProb, score: ngram.score, label: ngramLabel },
      charset: { lower: hasLower, upper: hasUpper, digit: hasDigit, symbol: hasSymbol, nonAscii: hasNonAscii }
    };
  }

  /* ------------------------------------------------------------------ */
  /* Generators                                                          */
  /* ------------------------------------------------------------------ */

  function generatePassword(options) {
    options = options || {};
    var length = options.length || 16;
    if (length < 8) length = 8;
    if (length > 64) length = 64;
    var sets = [];
    if (options.lower !== false) sets.push('abcdefghijklmnopqrstuvwxyz');
    if (options.upper !== false) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (options.digits !== false) sets.push('0123456789');
    if (options.symbols !== false) sets.push('!@#$%^&*()-_=+[]{};:,.<>?');
    if (sets.length === 0) sets.push('abcdefghijklmnopqrstuvwxyz');
    var all = sets.join('');
    var chars = [];
    sets.forEach(function (s) { chars.push(s[randomInt(s.length)]); });
    while (chars.length < length) chars.push(all[randomInt(all.length)]);
    for (var i = chars.length - 1; i > 0; i--) {
      var j = randomInt(i + 1);
      var tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp;
    }
    return chars.join('');
  }

  function generatePassphrase(wordCount) {
    wordCount = wordCount || 5;
    if (wordCount < 3) wordCount = 3;
    if (wordCount > 8) wordCount = 8;
    var words = [];
    for (var i = 0; i < wordCount; i++) words.push(WORDS[randomInt(WORDS.length)]);
    var bits = Math.round(wordCount * (Math.log(WORDS.length) / Math.log(2)) * 10) / 10;
    return { passphrase: words.join('-'), words: words, bits: bits, wordlistSize: WORDS.length };
  }

  return {
    version: VERSION,
    analyze: analyze,
    generatePassword: generatePassword,
    generatePassphrase: generatePassphrase,
    formatDuration: formatDuration,
    ngramPredictability: ngramPredictability,
    commonPasswordCount: COMMON_PASSWORDS.length,
    wordlistSize: WORDS.length,
    deleet: deleet
  };
});
