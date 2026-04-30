import pickle
import re
import math
import pandas as pd
from urllib.parse import urlparse
import tldextract


# -------- LOAD MODEL --------
model = pickle.load(open("model.pkl", "rb"))


# -------- CONFIG (MUST MATCH PREPROCESS) --------

brands = [
    "google","paypal","amazon","facebook",
    "apple","microsoft","bank","instagram"
]

trusted_domains = [
    "google.com","amazon.com","facebook.com",
    "apple.com","microsoft.com","paypal.com",
    "instagram.com","youtube.com","wikipedia.org"
]

keywords = [
    "login","verify","secure","update",
    "account","bank","confirm","password"
]

suspicious_tlds = ["xyz","top","ru","tk","cf","ml"]


# -------- FEATURE FUNCTIONS --------

def normalize(url):
    return url if url.startswith("http") else "http://" + url


def has_ip(url):
    return 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0


def subdomain_count(url):
    ext = tldextract.extract(url)
    return len(ext.subdomain.split('.')) if ext.subdomain else 0


def suspicious_tld(url):
    ext = tldextract.extract(url)
    return 1 if ext.suffix in suspicious_tlds else 0


def entropy(url):
    p = [url.count(c)/len(url) for c in set(url)]
    return -sum(x*math.log2(x) for x in p)


def keyword_score(url):
    u = url.lower()
    return sum(1 for k in keywords if k in u)


# ⭐ BRAND ABUSE DETECTION
def brand_abuse(url):
    domain = urlparse(url).netloc.lower()

    for b in brands:
        if b in domain:
            if domain.endswith(b + ".com"):
                return 0  # official site
            return 1      # impersonation

    return 0


# ⭐ TRUSTED DOMAIN FEATURE
def trusted_domain_feature(url):
    domain = urlparse(url).netloc.lower()
    return 1 if domain in trusted_domains else 0


# -------- FEATURE EXTRACTOR --------

def extract(url):

    url = normalize(url)

    return [
        len(url),
        url.count('.'),
        url.count('-'),
        sum(c.isdigit() for c in url),
        1 if '@' in url else 0,
        1 if url.startswith("https") else 0,
        has_ip(url),
        subdomain_count(url),
        suspicious_tld(url),
        keyword_score(url),
        entropy(url),
        brand_abuse(url),
        trusted_domain_feature(url)
    ]


# -------- TEST LOOP --------

print("\n🔍 Phishing URL Detector Ready")

while True:

    url = input("\nEnter URL (or type exit): ").strip()

    if url.lower() == "exit":
        break

    url_norm = normalize(url)
    domain = urlparse(url_norm).netloc.lower()

    # ⭐ HARD TRUST OVERRIDE (VERY IMPORTANT)
    if domain in trusted_domains:
        print("✅ SAFE (trusted domain)")
        continue

    # Extract features
    features = extract(url)

    # Match model feature names automatically
    df = pd.DataFrame([features], columns=model.feature_names_in_)

    # Predict
    pred = model.predict(df)[0]
    prob = model.predict_proba(df)[0][1]

    if pred == 1:
        print(f"⚠️ PHISHING | Confidence: {prob:.2f}")
    else:
        print(f"✅ SAFE | Confidence: {1-prob:.2f}")