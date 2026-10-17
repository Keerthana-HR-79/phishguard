"""Run:  pytest"""

import os
import tempfile

os.environ["PHISHGUARD_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")

from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402
from features import FEATURE_NAMES, extract_features, parse_host  # noqa: E402
import predict  # noqa: E402
from predict import BLOCKLIST, analyze, blocklist_key, normalize_url  # noqa: E402

client = TestClient(app)
FAKE_AGES = {"brand-new-shop.com": 5, "old-family-bakery.com": 4000}
predict.domain_age_days = FAKE_AGES.get   # no network in tests; unknown domains -> None


def test_feature_count():
    assert len(extract_features("https://example.com/a/b")) == len(FEATURE_NAMES) == 13


def test_parse_host():
    assert parse_host("https://www.Google.com:443/x") == "google.com"
    assert parse_host("http://paypal.com@evil.xyz/login") == "evil.xyz"
    assert parse_host("http-login.tk") == "http-login.tk"
    assert parse_host("http://[2001:db8::1]/") == "2001:db8::1"


def test_normalize_defanged():
    assert normalize_url("hxxp://evil[.]com//login") == "http://evil.com/login"


def test_trusted_domains_are_safe():
    for url in ["https://google.com", "https://www.amazon.in/orders", "https://github.com/login"]:
        assert analyze(url)["result"] == "SAFE", url


def test_hard_rules():
    assert analyze("http://45.12.67.89/login")["result"] == "PHISHING"
    assert analyze("https://paypa1.com@secure-update.xyz")["result"] == "PHISHING"
    assert analyze("http://paypal-verify-account.tk")["result"] == "PHISHING"
    assert analyze("http://xn--pple-43d.com/login")["result"] == "PHISHING"   # Cyrillic 'а'pple
    assert analyze("http://gооgle.com")["result"] == "PHISHING"              # raw Cyrillic 'оо'


def test_indian_brands():
    for url in ["http://sbi-kyc-update.com", "https://hdfc-netbanking.top/login",
                "http://ѕbi-login.com",                     # Cyrillic 'ѕ'
                "http://axisbank-kyc.in/verify", "http://yono-sbi-reward.com"]:
        assert analyze(url)["result"] == "PHISHING", url
    for url in ["https://onlinesbi.sbi", "https://sbi.co.in", "https://www.hdfcbank.com/login",
                "https://airtel.in", "https://www.jio.com"]:
        assert analyze(url)["result"] == "SAFE", url
    # 3-letter brands must not match inside ordinary words
    assert not any("Impersonates" in r or "Brand" in r
                   for r in analyze("https://public-library.org/catalog")["reasons"])


def test_blocklist():
    # a reported page on a trusted platform is flagged, matched without scheme/www/trailing '/'
    assert analyze("https://paypal-signin.blogspot.com")["result"] == "PHISHING"
    assert analyze("http://365msnpay.fwh.is")["reasons"][0].startswith("Reported")
    # ...but a trusted homepage can never be blocklisted
    assert blocklist_key("https://www.Google.com/") == "google.com" not in BLOCKLIST
    assert analyze("https://www.google.com/")["result"] == "SAFE"


def test_live_feed_refresh():
    fake_feed = "http://fresh-phish-page.example/login\n#comment\nhttps://www.google.com/\n"
    predict.FEED_URL = "data:text/plain," + fake_feed.replace("\n", "%0A")
    assert analyze("http://fresh-phish-page.example/login")["reasons"][0].startswith("ML")
    assert predict.refresh_feed() == 1                      # google.com is never blocklisted
    assert analyze("https://fresh-phish-page.example/login/")["result"] == "PHISHING"
    assert predict.feed_status["live_urls"] == 1 and predict.feed_status["last_error"] is None
    assert predict.refresh_feed() == 0                      # nothing new the second time
    predict.FEED_URL = "data:invalid"
    assert predict.refresh_feed() == 0 and predict.feed_status["last_error"]
    assert predict.feed_status["live_urls"] == 1            # a failed download keeps what we had


def test_model_runs_first_and_rules_override():
    for url, verdict in [("https://google.com", "SAFE"), ("http://45.12.67.89/login", "PHISHING"),
                         ("https://paypal-signin.blogspot.com", "PHISHING")]:
        r = analyze(url)
        assert r["result"] == verdict
        assert r["reasons"][1].startswith("ML:")            # model's opinion is still shown
        assert r["ml_probability"] not in (0.0, 1.0)         # a real score, not a placeholder


def test_localhost_in_path_is_not_a_bypass():
    assert "Localhost" not in analyze("http://evil.tk/localhost")["reasons"]
    assert "Localhost" not in analyze("http://127.evil-phish.com/login")["reasons"]   # not a loopback IP
    assert analyze("http://127.0.0.1:8000/")["reasons"][0] == "Localhost"
    assert analyze("http://[::1]/")["reasons"][0] == "Localhost"


def test_obvious_phishing_is_flagged():
    assert analyze("https://secure-login-update-account.com")["result"] != "SAFE"


def test_domain_age():
    new, old, unknown = (analyze(f"https://{d}") for d in
                         ["brand-new-shop.com", "old-family-bakery.com", "unknown-site.com"])
    assert new["domain_age_days"] == 5 and "registered only 5 days ago" in new["reasons"][-1]
    assert old["domain_age_days"] == 4000 and not any("Domain" in r for r in old["reasons"])
    assert unknown["domain_age_days"] is None
    assert new["risk_score"] > unknown["risk_score"] or new["risk_score"] == 10


def test_rate_limit():
    import app as app_module
    app_module.RATE_LIMIT_PER_MIN = 3
    try:
        ip = {"X-Forwarded-For": "203.0.113.9"}
        codes = [client.post("/predict_url", json={"url": "https://google.com"}, headers=ip).status_code
                 for _ in range(4)]
        assert codes == [200, 200, 200, 429]
        other = client.post("/predict_url", json={"url": "https://google.com"},
                            headers={"X-Forwarded-For": "203.0.113.10"})
        assert other.status_code == 200                     # limits are per client
    finally:
        app_module.RATE_LIMIT_PER_MIN = 120


def test_api_roundtrip():
    r = client.post("/predict_url", json={"url": "https://google.com"})
    assert r.status_code == 200 and r.json()["result"] == "SAFE"
    assert client.post("/predict_url", json={"url": "   "}).status_code == 400
    assert client.get("/stats").json()["total_scans"] >= 1
    assert client.get("/recent?limit=5").json()[0]["domain"] == "google.com"   # never the full URL
    health = client.get("/health").json()
    assert health["status"] == "ok" and health["blocklist_urls"] > 50_000 and "feed" in health
