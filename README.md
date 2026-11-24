# PassGuard — Honest Password Strength Checker

**SLAY HACKS 2026** · Live: https://devilking7x.github.io/slay-passguard/

How strong is your password, *really*? PassGuard answers with real maths —
not vibes, not fake breach lookups. Everything runs 100% in your browser:
no server, no tracking, nothing is ever sent anywhere.

## What it does

- **Entropy, honestly computed** — length × log₂ of the character pool
  actually used (26 per letter case, 10 digits, 32 symbols).
- **Pattern checks** — a built-in list of 206 widely published top-passwords
  (leet-speak like `P@ssw0rd` is caught too), keyboard walks (`qwerty`,
  `1qaz`), sequences (`abc`, `123`), repeats, and years.
- **Predictability model** — a small character-trigram statistical model
  trained on that same 206-password list. It scores how much a password
  "looks like" the passwords everybody picks. Deliberately small and
  labelled as such — a teaching-size model, not a breach database.
- **Crack-time estimates** — average guesses = 2^(effective entropy − 1),
  at two stated rates: online throttled login (100 guesses/sec) and
  offline fast hash on a GPU (10 billion guesses/sec). Labelled estimates,
  not guarantees.
- **Plain-language advice in English + Hindi** (हिन्दी toggle).
- **Generators** — a crypto-secure random password generator
  (`crypto.getRandomValues`, 12–32 chars) and a memorable passphrase
  generator (4–7 words from a 293-word list, honest bit count shown).

## Honest limits

- The common-password list is a small sample, not a breach database — a
  password can be "not found here" and still be leaked somewhere.
- Entropy assumes characters are random. A "strong" score does not protect
  a password that is reused, phished, or stored in plaintext by a website.
- Use a different password for every site, and turn on 2-step verification.

## Run it

Static site — no build step, no dependencies, no server. Open `index.html`
or serve the folder:

```sh
python3 -m http.server 8000
# open http://localhost:8000
```

## Tests

```sh
npm test          # 18 Node unit tests (node --test) for the core logic
npm run smoke     # 12 Playwright checks against the real page in Chromium
npm run test:all  # both
```

## Files

| File | What it is |
| --- | --- |
| `index.html` | The page |
| `styles.css` | Dark + gold styling, no frameworks |
| `app.js` | UI wiring + English/Hindi toggle |
| `passguard.js` | All analysis logic (UMD: browser + Node) |
| `tests/passguard.test.js` | Unit tests |
| `tests/smoke.mjs` | Playwright smoke test |

## Built by

Mohd Raja ([devilking7x](https://github.com/devilking7x)) for
[SLAY HACKS 2026](https://slayy-hacks.devpost.com/).
