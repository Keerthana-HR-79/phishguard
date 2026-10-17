"""
features.py — URL parsing helpers + the 13 hand-crafted URL features.

The model sees two things for every URL:
  1. TF-IDF character n-grams of the URL text   (built in train.py / predict.py)
  2. the 13 numbers returned by extract_features() below

Rule lists (brands, keywords, TLDs, trusted domains) live in rules.json.
"""

import ipaddress
import json
import math
import os
import re
import unicodedata
from urllib.parse import urlsplit

from rapidfuzz import fuzz

# ── Rules ─────────────────────────────────────────────────────────────────────
with open(os.path.join(os.path.dirname(__file__), "rules.json"), encoding="utf-8") as f:
    RULES = json.load(f)

BRANDS = RULES["brands"]
KEYWORDS = RULES["keywords"]
SUSPICIOUS_TLDS = set(RULES["suspicious_tlds"])
TRUSTED_ROOTS = set(RULES["trusted_roots"])
NOISE_ROOTS = set(RULES["noise_roots"])

FEATURE_NAMES = [
    "url_length", "dot_count", "host_hyphens", "path_depth", "digit_count",
    "entropy", "keyword_count", "host_keyword_tokens", "brand_similarity",
    "brand_spoof", "subdomain_count", "suspicious_tld", "idn_host",
]

# Look-alike letters (Cyrillic / Greek) used in homograph attacks → ASCII twin.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "һ": "h", "ԁ": "d", "ո": "n", "м": "m",
    "т": "t", "в": "b", "к": "k", "г": "r", "н": "h", "и": "u",
    "ο": "o", "α": "a", "ρ": "p", "ε": "e", "τ": "t", "ι": "i", "κ": "k",
    "ν": "v", "μ": "u", "χ": "x", "γ": "y", "π": "n", "θ": "o", "ⅼ": "l", "ӏ": "l",
})


# ── URL helpers (shared by train.py and predict.py) ───────────────────────────
def ensure_scheme(url: str) -> str:
    url = str(url).strip()
    return url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url) else "http://" + url


def parse_host(url: str) -> str:
    """Lowercase host without userinfo, port or leading 'www.'."""
    try:
        netloc = urlsplit(ensure_scheme(url)).netloc
    except ValueError:
        return ""
    netloc = netloc.rsplit("@", 1)[-1]
    if netloc.startswith("["):                       # [IPv6]:port
        host = netloc[1:].split("]", 1)[0]
    else:
        host = netloc.split(":", 1)[0]
    host = host.lower()
    return host[4:] if host.startswith("www.") else host


def root_domain(host: str) -> str:
    """Registrable domain: 'a.b.example.co.uk' -> 'example.co.uk'."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "ac", "gov", "net", "org", "edu", "com"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def has_at_trick(url: str) -> bool:
    """'http://paypal.com@evil.xyz' — an '@' in the authority hides the real host."""
    try:
        return "@" in urlsplit(ensure_scheme(url)).netloc
    except ValueError:
        return False


def _decode_idn(host: str) -> str:
    out = []
    for label in host.split("."):
        try:
            out.append(label[4:].encode().decode("punycode") if label.startswith("xn--") else label)
        except Exception:
            out.append(label)
    return ".".join(out)


def _skeleton(s: str) -> str:
    """Fold accents and look-alike letters to plain ASCII."""
    s = unicodedata.normalize("NFKD", s).translate(_CONFUSABLES)
    return "".join(c for c in s if ord(c) < 128)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def brand_match(host: str):
    """Return (similarity 0-1, spoofed brand or None).

    Each host piece (split on '.' and '-') is fuzzy-matched against every brand,
    after undoing homograph letters and digit swaps (0->o, 1->l, 3->e). A match
    whose registrable name is NOT that brand is a spoof (paypa1-login.com).
    """
    host_idn = _decode_idn(host)
    pieces = set(re.split(r"[.\-]", host)) | set(re.split(r"[.\-]", _skeleton(host_idn)))
    name = root_domain(host).split(".")[0]
    best, spoof = 0, None
    for piece in pieces:
        p = re.sub(r"[^a-z0-9]", "", piece).replace("0", "o").replace("1", "l").replace("3", "e")
        if len(p) < 4:
            continue
        for b in BRANDS:
            score = fuzz.ratio(p, b)
            if score > 85:
                best = max(best, score)
                if name != b:
                    spoof = b
    return best / 100, spoof


# ── The 13 features ───────────────────────────────────────────────────────────
def extract_features(url: str) -> list:
    url = ensure_scheme(str(url).lower().strip())
    host = parse_host(url)
    try:
        path = urlsplit(url).path
    except ValueError:
        path = ""
    parts = host.split(".")
    host_tokens = [t for t in re.split(r"[.\-]", host) if t]
    similarity, spoof = brand_match(host)

    return [
        len(url) / 100,                                          # url_length
        url.count("."),                                          # dot_count
        host.count("-"),                                         # host_hyphens
        len([p for p in path.split("/") if p]),                  # path_depth
        sum(c.isdigit() for c in url),                           # digit_count
        _entropy(url),                                           # entropy
        sum(k in url for k in KEYWORDS),                         # keyword_count
        sum(t in KEYWORDS for t in host_tokens),                 # host_keyword_tokens
        similarity,                                              # brand_similarity
        int(spoof is not None),                                  # brand_spoof
        max(len(parts) - 2, 0),                                  # subdomain_count
        int(parts[-1] in SUSPICIOUS_TLDS),                       # suspicious_tld
        int("xn--" in host or any(ord(c) > 127 for c in host)),  # idn_host
    ]
