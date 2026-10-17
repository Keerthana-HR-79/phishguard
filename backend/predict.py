"""
predict.py — turn a URL into a verdict: SAFE / SUSPICIOUS / PHISHING.

  Step 1  ML model    XGBoost phishing probability (0-1) for every URL
  Step 2  overrides   checked in order; the first that matches decides:
                        blocklist   URL reported in OpenPhish/PhishTank  -> PHISHING
                        allowlist   trusted domain or localhost          -> SAFE
                        hard rules  raw IP host, '@' trick, brand spoof  -> PHISHING
  Step 3  risk score  probability x 10 + brand checks + new-domain check -> thresholds -> verdict
"""

import datetime
import json
import os
import pickle
import re
import time
import urllib.request
from urllib.parse import urlsplit

import numpy as np
from rapidfuzz.distance import Levenshtein
from scipy.sparse import csr_matrix, hstack

from features import (BRANDS, KEYWORDS, SUSPICIOUS_TLDS, TRUSTED_ROOTS, brand_match, ensure_scheme,
                      extract_features, has_at_trick, is_ip, parse_host, root_domain)

_DIR = os.path.dirname(__file__)
with open(os.path.join(_DIR, "model.pkl"), "rb") as f:
    _bundle = pickle.load(f)
MODEL, VECTORIZER = _bundle["model"], _bundle["vectorizer"]

BRAND_BUMP = 2.5          # added per brand heuristic that fires
PHISHING_AT = 8.0         # risk score >= this -> PHISHING
SUSPICIOUS_AT = 6.0       # risk score >= this -> SUSPICIOUS

AGE_TIMEOUT_SEC = 3       # RDAP lookup timeout
NEW_DOMAIN_DAYS = 30      # younger than this -> + NEW_DOMAIN_BUMP
NEW_DOMAIN_BUMP = 3.0


def normalize_url(raw: str) -> str:
    """Trim, cap length, and undo 'defanged' notation (hxxp://evil[.]com)."""
    u = str(raw or "").strip()[:2048]
    u = re.sub(r"(?i)^hxxp", "http", u)
    u = re.sub(r"(?i)\[\s*dot\s*\]", ".", u).replace("[.]", ".").replace("(.)", ".")
    if not re.search(r"\[[0-9a-fA-F:]+\]", u):      # keep [IPv6] literals intact
        u = u.replace("[", "").replace("]", "")
    return re.sub(r"(?<!:)/{2,}", "/", u)           # byjus.com////login -> byjus.com/login


def blocklist_key(url: str) -> str:
    """'https://www.Evil.com/login/' -> 'evil.com/login' (ignores scheme, www, trailing '/')."""
    try:
        parts = urlsplit(ensure_scheme(url))
    except ValueError:
        return ""
    key = parse_host(url) + parts.path.rstrip("/")
    return key + "?" + parts.query if parts.query else key


def parse_blocklist(lines) -> set:
    """URL lines -> lookup keys. Skips blanks and '#' comments."""
    keys = set()
    for line in lines:
        if line.strip() and not line.startswith("#"):
            key = blocklist_key(normalize_url(line))
            # Never let a stale entry block a trusted homepage itself (e.g. 'google.com').
            if key and key not in TRUSTED_ROOTS:
                keys.add(key)
    return keys


with open(os.path.join(_DIR, "blocklist.txt"), encoding="utf-8") as f:
    BLOCKLIST = parse_blocklist(f)       # OpenPhish + PhishTank snapshot shipped with the code

# Live OpenPhish feed, downloaded by app.py at startup and every few hours.
# New URLs are added to what is already here (kept in memory until restart).
FEED_URL = "https://openphish.com/feed.txt"
LIVE_BLOCKLIST = set()
feed_status = {"last_refresh": None, "live_urls": 0, "last_error": None}


def refresh_feed() -> int:
    """Download the OpenPhish feed and add its URLs. Returns how many were new."""
    try:
        with urllib.request.urlopen(FEED_URL, timeout=30) as r:
            new = parse_blocklist(r.read().decode("utf-8", "ignore").splitlines())
    except Exception as e:
        feed_status["last_error"] = repr(e)
        return 0
    added = len(new - LIVE_BLOCKLIST - BLOCKLIST)
    LIVE_BLOCKLIST.update(new)
    feed_status.update(last_refresh=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                       live_urls=len(LIVE_BLOCKLIST), last_error=None)
    return added


_age_cache = {}   # root domain -> (lookup time, age in days or None)
_rdap_servers = None


def _rdap_server(tld: str):
    """Registry RDAP server for a TLD, from IANA's official list (fetched once).
    None for TLDs without RDAP (.de, .io, .ru ...). If the list can't be fetched,
    falls back to the rdap.org redirector, which rate-limits heavy use."""
    global _rdap_servers
    if _rdap_servers is None:
        try:
            with urllib.request.urlopen("https://data.iana.org/rdap/dns.json", timeout=5) as r:
                _rdap_servers = {t: s[0].rstrip("/") for tlds, s in json.load(r)["services"] for t in tlds}
        except Exception:
            return "https://rdap.org"
    return _rdap_servers.get(tld)


def domain_age_days(root: str):
    """Days since the domain was registered, via RDAP (WHOIS's JSON successor).
    Returns None when unknown (no RDAP for that TLD, timeout, offline)."""
    hit = _age_cache.get(root)
    if hit and time.time() - hit[0] < 24 * 3600:
        return hit[1]
    age = None
    server = _rdap_server(root.rsplit(".", 1)[-1])
    try:
        if not server:
            raise LookupError("no RDAP for this TLD")
        req = urllib.request.Request(f"{server}/domain/{root}", headers={"Accept": "application/rdap+json"})
        with urllib.request.urlopen(req, timeout=AGE_TIMEOUT_SEC) as r:
            events = json.load(r).get("events", [])
        for e in events:
            if e.get("eventAction") == "registration":
                created = datetime.datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
                age = (datetime.datetime.now(datetime.timezone.utc) - created).days
                break
    except Exception:
        pass
    if len(_age_cache) > 10_000:
        _age_cache.clear()
    _age_cache[root] = (time.time(), age)
    return age


def age_adjustment(age):
    """(score change, reason) for a domain age in days (None = unknown).
    Old domains get no discount: phishing on free hosts and hacked sites sits on
    old domains, and a discount lowered recall more than it saved false alarms."""
    if age is not None and age < NEW_DOMAIN_DAYS:
        return NEW_DOMAIN_BUMP, f"Domain registered only {age} days ago"
    return 0.0, None


def model_probability(url: str) -> float:
    text = VECTORIZER.transform([re.sub(r"^https?://", "", url.lower())])
    numeric = csr_matrix(np.array([extract_features(url)], dtype=np.float32))
    return float(MODEL.predict_proba(hstack([text, numeric]).tocsr())[0][1])


def _result(url, host, prob, score, reasons, age=None):
    score = round(min(score, 10.0), 2)
    verdict = "PHISHING" if score >= PHISHING_AT else "SUSPICIOUS" if score >= SUSPICIOUS_AT else "SAFE"
    return {"input": url, "domain": host, "ml_probability": round(prob, 4), "risk_score": score,
            "result": verdict, "reasons": reasons, "domain_age_days": age}


def _override(url, host):
    """Blocklist, allowlist and hard rules: (risk score, reason) when one decides
    the verdict outright, else None. Checked in this order."""
    root = root_domain(host)
    # blocklist before allowlist: phishing pages on docs.google.com, bit.ly,
    # blogspot.com... are reported URLs on otherwise trusted domains
    key = blocklist_key(url)
    if key in BLOCKLIST or key in LIVE_BLOCKLIST:
        return 10.0, "Reported in a known-phishing blocklist (OpenPhish/PhishTank)"
    if host == "localhost" or host.startswith("127.") or host == "::1":
        return 0.0, "Localhost"
    if root in TRUSTED_ROOTS:
        return 0.0, "Trusted domain"
    if is_ip(host):
        return 10.0, "Raw IP address used instead of a domain"
    if has_at_trick(url):
        return 10.0, "'@' in the address hides the real destination"
    _, spoofed = brand_match(host)
    if spoofed and (any(k in url.lower() for k in KEYWORDS)
                    or host.split(".")[-1] in SUSPICIOUS_TLDS
                    or "xn--" in host or any(ord(c) > 127 for c in host)):
        return 10.0, f"Impersonates '{spoofed}' with phishing signals"
    return None


def analyze(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    host = parse_host(url)
    if not host:
        raise ValueError("Could not find a domain in that URL")
    root = root_domain(host)
    name = root.split(".")[0]

    # Step 1: ML model scores every URL
    prob = model_probability(url)
    if prob >= 0.7:
        ml_reason = "ML: high phishing probability"
    elif prob >= 0.4:
        ml_reason = "ML: moderate phishing probability"
    else:
        ml_reason = "ML: low phishing probability"

    # Step 2: blocklist / allowlist / hard rules override the model
    decided = _override(url, host)
    if decided:
        score, reason = decided
        return _result(url, host, prob, score, [reason, ml_reason])

    # Step 3: model score + brand and domain-age checks
    score = prob * 10
    reasons = [ml_reason]

    subdomains = host.split(".")[:-len(root.split("."))]
    for brand in BRANDS:
        if brand in subdomains:
            score += BRAND_BUMP
            reasons.append(f"Brand '{brand}' used as a subdomain")
            break
    for brand in BRANDS:
        if brand in name and name != brand:
            score += BRAND_BUMP
            reasons.append(f"Brand '{brand}' inside an unrelated domain")
            break
    for brand in BRANDS:
        if Levenshtein.distance(name, brand) == 1:
            score += BRAND_BUMP
            reasons.append(f"Looks like a misspelling of '{brand}'")
            break

    age = domain_age_days(root)
    delta, why = age_adjustment(age)
    score = max(score + delta, 0.0)
    if why:
        reasons.append(why)

    return _result(url, host, prob, score, reasons, age)
