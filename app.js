/* PassGuard UI — wires the DOM to window.PassGuard (passguard.js).
   No network calls. The password never leaves this page. */
(function () {
  'use strict';

  var I18N = {
    en: {
      tagline: 'How strong is your password, really? Checked honestly — in your browser, nowhere else.',
      privacy: '100% private: your password never leaves this page. No server, no tracking, no breach lookup — everything is computed locally.',
      typeLabel: 'Type a password to check it',
      show: 'Show', hide: 'Hide', clear: 'Clear', try: 'Try an example:',
      entropy: 'Entropy', effectiveEntropy: 'After pattern penalties',
      crackTime: 'How long would it take to crack?',
      crackNote: 'Estimates, not guarantees. Assumptions stated below.',
      online: 'Online attack (throttled login, 100 guesses/sec)',
      offline: 'Offline attack (fast hash on a GPU, 10 billion guesses/sec)',
      predictability: 'Does it look like a common password?',
      predictNote: 'Small local statistical model (character trigrams trained on a built-in list of 206 common passwords). Higher = more like the passwords everybody picks.',
      findings: 'What we found', goodPoints: "What's good", advice: 'What to do',
      typeFirst: 'Type a password first.', typeFirst2: 'Type a password first.',
      genTitle: 'Need a strong one? Generate it here',
      genNote: "Generated with your device's secure random generator (crypto.getRandomValues). Nothing is stored or sent.",
      genPw: 'Random password', length: 'Length', symbols: 'Symbols', digits: 'Numbers',
      genPwBtn: 'Generate password', copy: 'Copy', copy2: 'Copy',
      genPhrase: 'Memorable passphrase', words: 'Words', genPhraseBtn: 'Generate passphrase',
      phraseBits: 'Strength',
      howTitle: 'How it works — no magic, no fake data',
      how1: 'Entropy: length × log₂ of the character pool actually used (26 per letter case, 10 digits, 32 symbols). A random 16-character mixed password is ~105 bits.',
      how2: 'Pattern checks: the password is tested against a built-in list of 206 widely published top-passwords (including leet-speak like P@ssw0rd), keyboard walks (qwerty, 1qaz), sequences (abc, 123), repeats, and years.',
      how3: 'Predictability model: a character-trigram model trained on that same 206-password list scores how much the password "looks like" a common one. Small and honest — it is a teaching-size model, not a breach database.',
      how4: 'Crack time: average guesses = 2^(effective entropy − 1), divided by a stated rate. Online: 100 guesses/sec (throttled login). Offline: 10 billion/sec (fast hash on a GPU).',
      limitsTitle: 'Honest limits',
      limit1: 'The common-password list is a small sample, not a breach database — a password can be "not found here" and still be leaked somewhere.',
      limit2: 'Entropy assumes characters are random. A "strong" score does not protect a password that is reused, phished, or stored in plaintext by a website.',
      limit3: 'Use a different password for every site, and turn on 2-step verification wherever it is offered.',
      builtBy: 'Built by', forHack: 'for',
      footNote: 'Static site, no build step, no server, no tracking. Works offline once loaded.',
      lower: 'a–z', upper: 'A–Z', digit: '0–9', symbol: 'symbols', nonAscii: 'non-ASCII',
      high: 'High', medium: 'Medium', low: 'Low',
      copied: 'Copied!',
      phraseBitsText: function (bits) { return '≈ ' + bits + ' bits — good for everyday accounts; use a generated password for high-value accounts.'; }
    },
    hi: {
      tagline: 'आपका पासवर्ड असल में कितना मज़बूत है? ईमानदारी से check — सिर्फ़ आपके browser में, कहीं और नहीं।',
      privacy: '100% private: आपका पासवर्ड इस page से कभी बाहर नहीं जाता। न server, न tracking, न breach lookup — सब कुछ locally compute होता है।',
      typeLabel: 'Check करने के लिए password लिखें',
      show: 'दिखाओ', hide: 'छुपाओ', clear: 'साफ़ करो', try: 'Example try करें:',
      entropy: 'Entropy', effectiveEntropy: 'Pattern penalty के बाद',
      crackTime: 'Crack करने में कितना time लगेगा?',
      crackNote: 'अनुमान है, guarantee नहीं। मान्यताएँ नीचे लिखी हैं।',
      online: 'Online attack (throttled login, 100 guesses/sec)',
      offline: 'Offline attack (GPU पर fast hash, 10 billion guesses/sec)',
      predictability: 'क्या यह आम पासवर्ड जैसा लगता है?',
      predictNote: 'छोटा local statistical model (206 आम passwords की list पर trained character trigrams)। ज़्यादा = सबके चुने हुए passwords जैसा।',
      findings: 'क्या मिला', goodPoints: 'क्या अच्छा है', advice: 'क्या करें',
      typeFirst: 'पहले password लिखें।', typeFirst2: 'पहले password लिखें।',
      genTitle: 'मज़बूत चाहिए? यहीं generate करें',
      genNote: 'आपके device के secure random generator (crypto.getRandomValues) से बनता है। कुछ store या send नहीं होता।',
      genPw: 'Random password', length: 'लंबाई', symbols: 'Symbol', digits: 'Number',
      genPwBtn: 'Password generate करें', copy: 'Copy', copy2: 'Copy',
      genPhrase: 'याद रखने लायक passphrase', words: 'शब्द', genPhraseBtn: 'Passphrase generate करें',
      phraseBits: 'मज़बूती',
      howTitle: 'कैसे काम करता है — न जादू, न fake data',
      how1: 'Entropy: लंबाई × log₂ (इस्तेमाल हुए characters का pool — हर letter case 26, digit 10, symbol 32)। Random 16-अक्षर mixed password ~105 bits होता है।',
      how2: 'Pattern check: password को 206 मशहूर top-passwords की built-in list से मिलाया जाता है (leet-speak जैसे P@ssw0rd समेत), keyboard walk (qwerty, 1qaz), sequence (abc, 123), repeat और साल।',
      how3: 'Predictability model: उसी 206-password list पर trained character-trigram model बताता है कि password आम password जैसा कितना लगता है। छोटा और ईमानदार model है — breach database नहीं।',
      how4: 'Crack time: average guesses = 2^(effective entropy − 1), एक मानी हुई rate से divide। Online: 100 guesses/sec (throttled login)। Offline: 10 billion/sec (GPU पर fast hash)।',
      limitsTitle: 'ईमानदार limits',
      limit1: 'आम passwords की list एक छोटा sample है, breach database नहीं — password यहाँ "नहीं मिला" तो भी कहीं leak हो सकता है।',
      limit2: 'Entropy मानता है कि अक्षर random हैं। "Strong" score उस password को नहीं बचाता जो दोबारा इस्तेमाल हो, phish हो, या website ने plaintext में रखा हो।',
      limit3: 'हर site के लिए अलग password रखें, और जहाँ मिले 2-step verification चालू करें।',
      builtBy: 'बनाया', forHack: 'के लिए',
      footNote: 'Static site, न build step, न server, न tracking। Load होने के बाद offline भी चलती है।',
      lower: 'a–z', upper: 'A–Z', digit: '0–9', symbol: 'symbol', nonAscii: 'non-ASCII',
      high: 'ज़्यादा', medium: 'बीच का', low: 'कम',
      copied: 'Copy हो गया!',
      phraseBitsText: function (bits) { return '≈ ' + bits + ' bits — रोज़ के accounts के लिए अच्छा; ज़्यादा ज़रूरी accounts के लिए generated password इस्तेमाल करें।'; }
    }
  };

  var lang = 'en';
  var $ = function (id) { return document.getElementById(id); };

  function t(key) { return I18N[lang][key] || I18N.en[key] || key; }

  function bandClass(label) {
    return label.toLowerCase().replace(/ /g, '-');
  }

  function render(result) {
    var score = result.score;
    $('score-value').textContent = score;
    var bandEl = $('band-label');
    bandEl.textContent = lang === 'hi' ? result.band.hi : result.band.label;
    bandEl.className = 'band ' + bandClass(result.band.label);
    $('meter').setAttribute('aria-valuenow', String(score));
    var fill = $('meter-fill');
    fill.style.width = score + '%';
    fill.style.background = score < 20 ? 'var(--red)' : score < 40 ? '#e07b39' : score < 60 ? 'var(--amber)' : score < 80 ? '#8fd07a' : 'var(--green)';

    $('entropy-value').textContent = result.entropy + ' bits';
    $('effective-entropy-value').textContent = result.effectiveEntropy + ' bits';
    $('crack-online').textContent = result.crackTime.online;
    $('crack-offline').textContent = result.crackTime.offline;

    var ng = $('ngram-fill');
    ng.style.width = Math.round(result.ngram.score * 100) + '%';
    ng.style.background = result.ngram.score >= 0.66 ? 'var(--red)' : result.ngram.score >= 0.33 ? 'var(--amber)' : 'var(--green)';
    var ngramWord = result.ngram.label === 'High' ? t('high') : result.ngram.label === 'Medium' ? t('medium') : result.ngram.label === 'Low' ? t('low') : result.ngram.label;
    $('ngram-label').textContent = ngramWord;
    $('ngram-score').textContent = Math.round(result.ngram.score * 100) + '% predictable · log-prob ' + result.ngram.logProb;

    var chips = [];
    if (result.charset.lower) chips.push(t('lower'));
    if (result.charset.upper) chips.push(t('upper'));
    if (result.charset.digit) chips.push(t('digit'));
    if (result.charset.symbol) chips.push(t('symbol'));
    if (result.charset.nonAscii) chips.push(t('nonAscii'));
    $('charset-chips').innerHTML = chips.map(function (c) {
      return '<span class="chip on">' + c + '</span>';
    }).join('') || '<span class="muted">–</span>';

    var findingsEl = $('findings');
    if (result.findings.length === 0) {
      findingsEl.innerHTML = '<li class="good">' + (lang === 'hi' ? 'कोई आम pattern नहीं मिला।' : 'No common patterns detected.') + '</li>';
    } else {
      findingsEl.innerHTML = result.findings.map(function (f) {
        var cls = f.severity === 'critical' ? 'bad' : f.severity === 'info' ? '' : 'bad';
        return '<li class="' + cls + '">' + (lang === 'hi' ? f.hi : f.en) + '</li>';
      }).join('');
    }

    var posEl = $('positives');
    posEl.innerHTML = result.positives.length === 0
      ? '<li class="muted">–</li>'
      : result.positives.map(function (p) {
          return '<li class="good">' + (lang === 'hi' ? p.hi : p.en) + '</li>';
        }).join('');

    $('advice').innerHTML = result.advice.map(function (a) {
      return '<li>' + (lang === 'hi' ? a.hi : a.en) + '</li>';
    }).join('');
  }

  function check() {
    render(window.PassGuard.analyze($('password').value));
  }

  function applyLang() {
    document.querySelectorAll('[data-i18n]').forEach(function (el) {
      var key = el.getAttribute('data-i18n');
      var val = I18N[lang][key];
      if (typeof val === 'string') el.textContent = val;
    });
    $('lang-toggle').textContent = lang === 'en' ? 'हिन्दी' : 'English';
    document.documentElement.lang = lang === 'hi' ? 'hi' : 'en';
    check();
  }

  function copyText(text, btn) {
    var done = function () {
      var old = btn.textContent;
      btn.textContent = t('copied');
      setTimeout(function () { btn.textContent = old; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallbackCopy(text); done(); });
    } else {
      fallbackCopy(text);
      done();
    }
  }

  function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* ignore */ }
    document.body.removeChild(ta);
  }

  document.addEventListener('DOMContentLoaded', function () {
    $('password').addEventListener('input', check);

    $('toggle-visibility').addEventListener('click', function () {
      var input = $('password');
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      this.querySelector('span').textContent = show ? t('hide') : t('show');
    });

    $('clear-btn').addEventListener('click', function () {
      $('password').value = '';
      check();
      $('password').focus();
    });

    document.querySelectorAll('.example').forEach(function (btn) {
      btn.addEventListener('click', function () {
        $('password').value = btn.getAttribute('data-pw');
        check();
      });
    });

    $('lang-toggle').addEventListener('click', function () {
      lang = lang === 'en' ? 'hi' : 'en';
      applyLang();
    });

    $('pw-length').addEventListener('input', function () {
      $('pw-length-value').textContent = this.value;
    });
    $('phrase-words').addEventListener('input', function () {
      $('phrase-words-value').textContent = this.value;
    });

    $('gen-password-btn').addEventListener('click', function () {
      var pw = window.PassGuard.generatePassword({
        length: parseInt($('pw-length').value, 10),
        symbols: $('opt-symbols').checked,
        digits: $('opt-digits').checked
      });
      $('gen-password-output').textContent = pw;
    });

    $('copy-password-btn').addEventListener('click', function () {
      var txt = $('gen-password-output').textContent;
      if (txt && txt !== '–') copyText(txt, this);
    });

    $('gen-passphrase-btn').addEventListener('click', function () {
      var r = window.PassGuard.generatePassphrase(parseInt($('phrase-words').value, 10));
      $('gen-passphrase-output').textContent = r.passphrase;
      $('phrase-bits').textContent = t('phraseBitsText')(r.bits);
    });

    $('copy-passphrase-btn').addEventListener('click', function () {
      var txt = $('gen-passphrase-output').textContent;
      if (txt && txt !== '–') copyText(txt, this);
    });

    check();
  });
})();
