import pickle
import re
import math
import json
import os
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import tldextract


# -------- LOAD MODEL --------
model = pickle.load(open("model.pkl", "rb"))

# -------- LOAD SHAP EXPLAINER (optional) --------
explainer = None
SHAP_PATH = "shap_outputs/explainer.pkl"
if os.path.exists(SHAP_PATH):
    try:
        explainer = pickle.load(open(SHAP_PATH, "rb"))
        print("🔍 SHAP explainer loaded")
    except Exception:
        print("⚠️  Could not load SHAP explainer")


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

feature_names = [
    "length","dot_count","hyphen_count","digit_count",
    "at_symbol","ssl_flag","ip_flag","subdomain_count",
    "suspicious_tld","keyword_score","entropy",
    "brand_abuse","trusted_domain"
]


# -------- FEATURE FUNCTIONS --------

def normalize(url):
    url = str(url).strip()
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
    if len(url) == 0:
        return 0
    p = [url.count(c)/len(url) for c in set(url)]
    return -sum(x*math.log2(x) for x in p)


def keyword_score(url):
    u = url.lower()
    return sum(1 for k in keywords if k in u)


def brand_abuse(url):
    domain = urlparse(url).netloc.lower()
    for b in brands:
        if b in domain:
            if domain.endswith(b + ".com"):
                return 0
            return 1
    return 0


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


def get_threat_tier(score):
    """Convert threat score (0-100) to 3-tier label."""
    if score <= 30:
        return "SAFE"
    elif score <= 70:
        return "WARN"
    else:
        return "BLOCK"


def get_shap_explanation(features_df):
    """Get SHAP-based explanation for a single prediction."""
    if explainer is None:
        return None

    try:
        shap_values = explainer.shap_values(features_df)

        # For binary classification
        if isinstance(shap_values, list):
            vals = shap_values[1][0]
        else:
            vals = shap_values[0]

        # Create explanation dict
        explanations = []
        for name, val in sorted(zip(feature_names, vals), key=lambda x: abs(x[1]), reverse=True):
            if abs(val) > 0.01:
                direction = "increases" if val > 0 else "decreases"
                explanations.append({
                    "feature": name,
                    "impact": round(float(val), 4),
                    "direction": direction
                })

        return explanations[:5]  # Top 5 contributing features
    except Exception:
        return None


# -------- TEST LOOP --------

print("\n🔍 Phishing URL Detector Ready (Enhanced)")
print("   Features: threat_score (0-100) | Labels: SAFE / WARN / BLOCK")
print("   Type 'exit' to quit\n")

while True:
    url = input("Enter URL: ").strip()

    if url.lower() == "exit":
        break

    url_norm = normalize(url)
    domain = urlparse(url_norm).netloc.lower()

    # ⭐ HARD TRUST OVERRIDE
    if domain in trusted_domains:
        print(f"   ✅ SAFE | Score: 0 | Trusted domain: {domain}\n")
        continue

    # Extract features
    features = extract(url)
    df = pd.DataFrame([features], columns=model.feature_names_in_)

    # Predict
    prob = model.predict_proba(df)[0][1]  # Probability of phishing
    threat_score = round(prob * 100, 1)
    threat_label = get_threat_tier(threat_score)

    # Display
    if threat_label == "SAFE":
        icon = "✅"
    elif threat_label == "WARN":
        icon = "⚠️ "
    else:
        icon = "🚫"

    print(f"   {icon} {threat_label} | Threat Score: {threat_score}/100 | Confidence: {prob:.3f}")

    # SHAP explanation
    explanation = get_shap_explanation(df)
    if explanation:
        print("   📋 Key factors:")
        for exp in explanation:
            arrow = "↑" if exp["direction"] == "increases" else "↓"
            print(f"      {arrow} {exp['feature']}: {exp['impact']:+.4f}")

    print()