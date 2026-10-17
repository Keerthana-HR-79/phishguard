# PhishGuard AI (simplified)

Phishing URL detector: a FastAPI backend with an XGBoost model, a small website
(URL checker + dashboard) and a Chrome extension.

```
backend/
  features.py      URL parsing + the 13 hand-crafted features
  train.py         trains the model -> model.pkl
  predict.py       allowlist -> hard rules -> model -> verdict
  app.py           FastAPI endpoints
  database.py      SQLite scan log (30-day retention) for the dashboard
  rules.json       brands, keywords, suspicious TLDs, trusted domains
  blocklist.txt    ~58k known phishing URLs (OpenPhish + PhishTank snapshot)
  model.pkl        trained XGBoost model + TF-IDF vectorizer
  test_app.py      tests
extension/         Chrome extension (Manifest V3)
frontend/          index.html (checker), dashboard.html, app.js, style.css
data/              training CSVs (not committed)
```

## How a URL is judged

1. **ML model.** XGBoost gives every URL a phishing probability from 0 to 1.
   It is always reported as `ml_probability`, even when a rule decides the verdict.
2. **Overrides.** These are checked in this order, and the first one that matches decides the verdict:
   1. **Blocklist.** The URL was reported in OpenPhish or PhishTank → PHISHING (risk 10).
      - Matching ignores `http`/`https`, `www.` and a trailing `/`.
      - It comes *before* the allowlist, because many reported pages live on trusted platforms
        (`docs.google.com/forms/...`, `bit.ly/...`, `*.blogspot.com`).
      - A trusted homepage itself (e.g. `google.com`) can never be blocklisted.
      - Two sources:
        - `backend/blocklist.txt`: a snapshot of about 58k OpenPhish + PhishTank URLs, shipped with the code.
        - The live OpenPhish feed (`https://openphish.com/feed.txt`): downloaded in the background when
          the API starts, then every 6 hours. New URLs are added in memory; a failed download keeps what's
          already there. `/health` shows when it last refreshed and how many live URLs it has.
          Set `PHISHGUARD_FEED=off` to disable it.
   2. **Allowlist.** Localhost or a trusted domain from `rules.json` → SAFE (risk 0).
   3. **Hard rules.** Any of these → PHISHING (risk 10):
      - a raw IP address used as the host
      - an `@` in the address (`paypal.com@evil.xyz`)
      - a look-alike of a brand name together with a phishing word, a suspicious TLD or a punycode/Unicode host
3. **Risk score.** If no override matched, the score is the model's probability × 10, plus:
   - 2.5 for each brand check that fires: brand used as a subdomain, brand inside another domain name,
     or a one-letter misspelling of a brand
   - 3 if the domain was registered less than 30 days ago
     - Domain age comes from RDAP (the JSON successor of WHOIS) through each registry's server in IANA's list.
       The lookup has a 3 s timeout, and results are cached for 24 hours.
     - Some TLDs (`.de`, `.io`, `.ru`) have no public RDAP, so their age is unknown and nothing is added.

   Then: score ≥ 8 → PHISHING, score ≥ 6 → SUSPICIOUS, otherwise SAFE.

### Model features

- **TF-IDF character n-grams** (3–5 characters, 3,000 features) of the URL without `http://`
- **13 numeric features:**
  - URL length, dot count, hyphens in host, path depth, digit count, entropy
  - phishing-keyword count, keywords as host tokens
  - brand similarity, brand-spoof flag
  - subdomain count, suspicious TLD, punycode/Unicode host

### Training (`train.py`)

1. Load the phishing and legitimate URLs.
2. Drop label noise (trusted domains labelled phishing, shortener and free-hosting domains).
3. Balance the two classes.
4. Add every URL twice, once bare and once with a random path. This applies to both classes, so
   the model learns from the host and not from "has a path".
5. Split by domain, so no domain appears in both train and test.

## Run locally

```bash
cd backend
pip install -r requirements.txt
uvicorn app:app --reload          # API on http://127.0.0.1:8000
```

Open `frontend/index.html` through any static server (e.g. `python -m http.server 5500 -d frontend`).
On localhost it talks to `http://127.0.0.1:8000`.

**Chrome extension:**
1. Open `chrome://extensions` and turn on Developer mode.
2. Click **Load unpacked** and select the `extension/` folder.
3. To use a local backend, change `API_BASE` at the top of `extension/background.js`.

**Retrain:** put the CSVs in `data/`, then run `python train.py` in `backend/`. **Tests:** run `pytest` in `backend/`.

## API

| Method | Path | Returns |
|---|---|---|
| POST | `/predict_url` `{"url": "..."}` | `result`, `risk_score` (0–10), `ml_probability`, `reasons`, `domain` |
| GET | `/stats` | totals, detection rate, 7-day breakdown, most-flagged URLs |
| GET | `/recent?limit=20` | latest scans |
| GET | `/health` | status, blocklist size, live-feed status (last refresh, live URLs, last error) |

## Deploy

The backend runs on Render (`render.yaml`) and the frontend on Vercel (`vercel.json`).
