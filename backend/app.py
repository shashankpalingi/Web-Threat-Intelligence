from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
import pickle
import re
import math
import json
import os
import numpy as np
import pandas as pd
from urllib.parse import urlparse
import tldextract
from database import init_db, log_scan, get_scan_history, get_stats


# -------- LOAD MODEL --------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "..", "ml", "model.pkl")
SHAP_EXPLAINER_PATH = os.path.join(BASE_DIR, "..", "ml", "shap_outputs", "explainer.pkl")
SHAP_IMPORTANCE_PATH = os.path.join(BASE_DIR, "..", "ml", "shap_outputs", "feature_importance.json")
EVAL_RESULTS_PATH = os.path.join(BASE_DIR, "..", "ml", "evaluation_results.json")

model = pickle.load(open(MODEL_PATH, "rb"))

# Load SHAP explainer (optional)
explainer = None
if os.path.exists(SHAP_EXPLAINER_PATH):
    try:
        explainer = pickle.load(open(SHAP_EXPLAINER_PATH, "rb"))
        print("🔍 SHAP explainer loaded")
    except Exception as e:
        print(f"⚠️  Could not load SHAP explainer: {e}")

# Load global feature importance
global_importance = {}
if os.path.exists(SHAP_IMPORTANCE_PATH):
    with open(SHAP_IMPORTANCE_PATH) as f:
        global_importance = json.load(f)


# -------- APP SETUP --------

app = FastAPI(title="AI-Powered Web Threat Detection API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------- CONFIG --------

brands = [
    "google","paypal","amazon","facebook",
    "apple","microsoft","bank","instagram"
]

trusted_domains = [
    "google.com","amazon.com","facebook.com",
    "apple.com","microsoft.com","paypal.com",
    "instagram.com","youtube.com","wikipedia.org"
]

# Known legitimate hosting/cloud platforms
# Sites on these platforms get a score adjustment since the platform itself is trusted
trusted_platforms = [
    "netlify.app", "vercel.app", "github.io", "herokuapp.com",
    "web.app", "firebaseapp.com", "pages.dev", "surge.sh",
    "onrender.com", "railway.app", "fly.dev", "azurewebsites.net",
    "cloudfront.net", "amplifyapp.com"
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


def is_trusted_platform(domain):
    """Check if a domain is hosted on a known legitimate platform."""
    for platform in trusted_platforms:
        if domain.endswith(platform):
            return platform
    return None


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
        return []

    try:
        shap_values = explainer.shap_values(features_df)

        if isinstance(shap_values, list):
            vals = shap_values[1][0]
        else:
            vals = shap_values[0]

        explanations = []
        for name, val, feat_val in sorted(
            zip(feature_names, vals, features_df.values[0]),
            key=lambda x: abs(x[1]), reverse=True
        ):
            if abs(val) > 0.005:
                explanations.append({
                    "feature": name,
                    "impact": round(float(val), 4),
                    "value": round(float(feat_val), 4),
                    "direction": "risk" if val > 0 else "safe"
                })

        return explanations[:6]
    except Exception:
        return []


# -------- ROUTES --------

@app.get("/")
def home():
    return {
        "service": "AI-Powered Web Threat Detection API",
        "version": "2.0",
        "endpoints": ["/check", "/history", "/stats", "/model-info"]
    }


@app.post("/check")
def check_url(url: str):
    """Analyze a URL for phishing/scam threats."""

    url_norm = normalize(url)
    domain = urlparse(url_norm).netloc.lower()

    # ⭐ HARD TRUST OVERRIDE
    if domain in trusted_domains:
        result = {
            "url": url,
            "domain": domain,
            "threat_score": 0,
            "threat_label": "SAFE",
            "prediction": "SAFE",
            "confidence": 1.0,
            "reason": "Trusted domain",
            "explanation": [{"feature": "trusted_domain", "impact": 0, "value": 1, "direction": "safe"}]
        }

        log_scan(
            url=url, domain=domain, threat_score=0,
            threat_label="SAFE", prediction="SAFE", confidence=1.0,
            explanation=[{"feature": "trusted_domain"}]
        )

        return result

    # Extract features
    features = extract(url)
    features_dict = dict(zip(feature_names, features))
    df = pd.DataFrame([features], columns=model.feature_names_in_)

    # Predict
    prob = model.predict_proba(df)[0][1]  # Probability of phishing
    threat_score = round(prob * 100, 1)

    # ⭐ PLATFORM-AWARE ADJUSTMENT
    # Hosting platforms (netlify, vercel, etc.) trigger false positives
    # because their subdomain structure looks like phishing to the model.
    # If the URL is on a trusted platform AND has no phishing keywords
    # or brand abuse, reduce the score significantly.
    platform = is_trusted_platform(domain)
    if platform:
        has_keywords = features_dict.get("keyword_score", 0) > 0
        has_brand_abuse = features_dict.get("brand_abuse", 0) > 0
        if not has_keywords and not has_brand_abuse:
            # Legitimate app on trusted platform — cap at SAFE range
            threat_score = min(threat_score, 15.0)
        elif not has_brand_abuse:
            # Has keywords but no brand abuse — mild adjustment
            threat_score = min(threat_score, 45.0)

    threat_label = get_threat_tier(threat_score)
    pred = model.predict(df)[0]
    prediction = "PHISHING" if threat_label == "BLOCK" else ("SUSPICIOUS" if threat_label == "WARN" else "SAFE")
    confidence = float(prob) if pred == 1 else float(1 - prob)

    # SHAP explanation
    explanation = get_shap_explanation(df)
    if platform:
        explanation.insert(0, {
            "feature": "trusted_platform",
            "impact": -0.5,
            "value": 1,
            "direction": "safe",
            "note": f"Hosted on {platform}"
        })

    result = {
        "url": url,
        "domain": domain,
        "threat_score": threat_score,
        "threat_label": threat_label,
        "prediction": prediction,
        "confidence": round(confidence, 3),
        "features": features_dict,
        "explanation": explanation
    }

    # Log to database
    log_scan(
        url=url, domain=domain, threat_score=threat_score,
        threat_label=threat_label, prediction=prediction,
        confidence=confidence, features=features_dict,
        explanation=explanation
    )

    return result


@app.get("/history")
def history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    label: str = Query(None)
):
    """Get scan history from the threat database."""
    scans = get_scan_history(limit=limit, offset=offset, label_filter=label)
    return {"scans": scans, "count": len(scans)}


@app.get("/stats")
def stats():
    """Get aggregated threat statistics."""
    return get_stats()


@app.get("/model-info")
def model_info():
    """Get model metadata and feature importance."""
    info = {
        "feature_names": feature_names,
        "global_feature_importance": global_importance,
        "shap_available": explainer is not None,
    }

    if os.path.exists(EVAL_RESULTS_PATH):
        with open(EVAL_RESULTS_PATH) as f:
            info["evaluation"] = json.load(f)

    return info