"""
train.py — train the PhishGuard model and save it to model.pkl.

Steps:
  1. load phishing + legitimate URLs from ../data/
  2. clean label noise (trusted domains labelled phishing, shared-hosting roots)
  3. balance the classes
  4. augment: every URL appears once bare and once with a random path, for BOTH
     classes, so the model learns from the HOST and not from "has a path"
  5. split by domain (no domain in both train and test)
  6. features = TF-IDF char n-grams + 13 hand-crafted features
  7. train XGBoost, print test metrics, save {model, vectorizer} to model.pkl

Run:  python train.py
"""

import os
import pickle
import random
import re

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

from features import NOISE_ROOTS, TRUSTED_ROOTS, extract_features, parse_host, root_domain

DATA = os.path.join(os.path.dirname(__file__), "..", "data")
MAX_PER_CLASS = 100_000
SEED = 42

PATHS = [
    "/", "/home", "/about", "/contact", "/pricing", "/faq", "/help", "/support",
    "/blog/2024/03/getting-started", "/news/latest", "/products/item/1042",
    "/category/electronics/phones", "/cart", "/checkout", "/search?q=shoes",
    "/docs/getting-started", "/api/v1/status", "/dashboard", "/user/profile",
    "/settings", "/login", "/signin", "/account", "/account/settings",
    "/secure/checkout", "/verify-email", "/reset-password", "/billing",
    "/security/2fa", "/update-profile", "/confirm?token=a1b2c3", "/auth/callback",
    "/wp-login.php", "/wp-admin", "/portal",
]
SEGMENTS = [
    "login", "signin", "verify", "account", "secure", "update", "confirm",
    "billing", "auth", "user", "profile", "reset", "password", "home", "app",
    "dashboard", "portal", "settings", "orders", "products", "search", "en", "v1",
]


def bare(url: str) -> str:
    return "http://" + parse_host(url)


def with_path(url: str, rng: random.Random) -> str:
    if rng.random() < 0.35:   # deep keyword-stacked path, for both classes
        return bare(url) + "/" + "/".join(rng.choice(SEGMENTS) for _ in range(rng.randint(2, 7)))
    return bare(url) + rng.choice(PATHS)


def to_matrix(urls, vectorizer):
    text = [re.sub(r"^https?://", "", u) for u in urls]
    numeric = csr_matrix(np.array([extract_features(u) for u in urls], dtype=np.float32))
    return hstack([vectorizer.transform(text), numeric]).tocsr()


def main():
    # 1. load
    phishing = pd.concat([
        pd.read_csv(f"{DATA}/final_dataset.csv").query("type == 'phishing'"),
        pd.read_csv(f"{DATA}/adversarial_phishing.csv"),
        pd.read_csv(f"{DATA}/fresh_phishing.csv"),
    ])
    legit = pd.concat([
        pd.read_csv(f"{DATA}/final_dataset.csv").query("type == 'legitimate'"),
        pd.read_csv(f"{DATA}/legit_urls.csv"),
    ])
    phishing = phishing.dropna(subset=["url"]).drop_duplicates("url")
    legit = legit.dropna(subset=["url"]).drop_duplicates("url")

    # 2. clean label noise
    phishing["root"] = phishing["url"].map(lambda u: root_domain(parse_host(u)))
    legit["root"] = legit["url"].map(lambda u: root_domain(parse_host(u)))
    phishing = phishing[~phishing["root"].isin(TRUSTED_ROOTS | NOISE_ROOTS)]
    legit = legit[~legit["root"].isin(NOISE_ROOTS)]

    # 3. balance
    n = min(len(phishing), len(legit), MAX_PER_CLASS)
    print(f"Using {n:,} phishing + {n:,} legitimate URLs")
    data = pd.concat([phishing.sample(n, random_state=SEED).assign(label=1),
                      legit.sample(n, random_state=SEED).assign(label=0)])

    # 4. augment: bare + pathed copy of every URL
    rng = random.Random(SEED)
    rows = []
    for url, label in zip(data["url"], data["label"]):
        if "." in parse_host(url):
            rows.append((bare(url), label))
            rows.append((with_path(url, rng), label))
    aug = pd.DataFrame(rows, columns=["url", "label"]).drop_duplicates("url")
    urls, y = aug["url"].tolist(), aug["label"].values
    groups = [root_domain(parse_host(u)) for u in urls]

    # 5. split by domain
    train_idx, test_idx = next(GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
                               .split(urls, y, groups))
    train_urls = [urls[i] for i in train_idx]
    test_urls = [urls[i] for i in test_idx]
    print(f"Train: {len(train_urls):,} rows   Test: {len(test_urls):,} rows (unseen domains)")

    # 6. features
    print("Extracting features...")
    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), max_features=3000)
    vectorizer.fit([re.sub(r"^https?://", "", u) for u in train_urls])
    vectorizer.stop_words_ = None   # only needed during fit; keeps model.pkl small
    X_train, X_test = to_matrix(train_urls, vectorizer), to_matrix(test_urls, vectorizer)

    # 7. train + evaluate
    print("Training XGBoost...")
    model = XGBClassifier(n_estimators=400, max_depth=7, learning_rate=0.05,
                          tree_method="hist", random_state=SEED, n_jobs=-1)
    model.fit(X_train, y[train_idx])

    pred = model.predict(X_test)
    print(classification_report(y[test_idx], pred, target_names=["legitimate", "phishing"], digits=3))
    print("Confusion matrix [legit, phishing]:", confusion_matrix(y[test_idx], pred).tolist())

    with open(os.path.join(os.path.dirname(__file__), "model.pkl"), "wb") as f:
        pickle.dump({"model": model, "vectorizer": vectorizer}, f)
    print("Saved model.pkl")


if __name__ == "__main__":
    main()
