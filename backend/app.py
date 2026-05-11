from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import pickle
import re
import math
import json
import os
import numpy as np
import pandas as pd
from urllib.parse import urlparse, parse_qs
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


# -------- NLP CONFIG --------

# Homoglyph map — characters that look similar and are used in typosquatting
HOMOGLYPH_MAP = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '@': 'a', '!': 'i', '$': 's',
    'ö': 'o', 'ä': 'a', 'ü': 'u', 'é': 'e', 'è': 'e',
    'ñ': 'n', 'ç': 'c', 'ī': 'i', 'ó': 'o', 'ú': 'u',
}

# Suspicious n-grams commonly found in phishing URLs
PHISHING_NGRAMS = [
    "login", "signin", "verify", "secure", "update", "confirm",
    "account", "password", "banking", "wallet", "paypal", "amazn",
    "googl", "faceb", "micro", "apple", "icloud", "netflix",
    "whatsapp", "telegram", "crypto", "recover", "suspend",
    "urgent", "alert", "locked", "expire", "renew", "invoice",
    "refund", "reward", "winner", "prize", "free", "gift",
    "click", "action", "required", "immediately"
]

# Threat lexicon — words/patterns that strongly suggest malicious intent
THREAT_LEXICON = {
    "high": ["phishing", "malware", "trojan", "keylogger", "ransomware",
             "credential", "steal", "hack", "exploit", "injection"],
    "medium": ["login", "signin", "verify", "secure", "update", "confirm",
               "password", "account", "suspend", "locked", "expire", "urgent"],
    "low": ["free", "gift", "winner", "prize", "reward", "click", "offer",
            "bonus", "discount", "promo"]
}


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


def strip_www(domain):
    """Remove www. prefix from domain for matching."""
    return domain[4:] if domain.startswith("www.") else domain


def brand_abuse(url):
    domain = strip_www(urlparse(url).netloc.lower())
    for b in brands:
        if b in domain:
            if domain.endswith(b + ".com"):
                return 0
            return 1
    return 0


def trusted_domain_feature(url):
    domain = strip_www(urlparse(url).netloc.lower())
    return 1 if domain in trusted_domains else 0


def is_trusted_platform(domain):
    """Check if a domain is hosted on a known legitimate platform."""
    for platform in trusted_platforms:
        if domain.endswith(platform):
            return platform
    return None


# -------- NLP ANALYSIS FUNCTIONS --------

def nlp_ngram_analysis(url):
    """Analyze URL for suspicious character n-grams commonly found in phishing."""
    url_lower = url.lower()
    found_ngrams = []
    for ngram in PHISHING_NGRAMS:
        if ngram in url_lower:
            found_ngrams.append(ngram)

    risk_score = min(len(found_ngrams) * 15, 100)
    return {
        "suspicious_ngrams": found_ngrams,
        "ngram_count": len(found_ngrams),
        "risk_contribution": risk_score
    }


def nlp_homoglyph_detection(url):
    """Detect homoglyph/typosquatting attacks in the domain."""
    parsed = urlparse(normalize(url))
    domain = strip_www(parsed.netloc.lower())
    ext = tldextract.extract(url)
    domain_name = ext.domain  # Just the domain part, without TLD

    # Check for homoglyph substitutions
    homoglyphs_found = []
    normalized_domain = domain_name
    for char, replacement in HOMOGLYPH_MAP.items():
        if char in domain_name:
            homoglyphs_found.append({
                "original": char,
                "looks_like": replacement,
                "position": domain_name.index(char)
            })
            normalized_domain = normalized_domain.replace(char, replacement)

    # Check if normalized domain matches any known brand
    brand_match = None
    if homoglyphs_found:
        for brand in brands:
            if brand in normalized_domain and brand not in domain_name:
                brand_match = brand
                break

    is_suspicious = len(homoglyphs_found) > 0 and brand_match is not None
    return {
        "homoglyphs_detected": homoglyphs_found,
        "normalized_domain": normalized_domain,
        "suspected_impersonation": brand_match,
        "is_typosquatting": is_suspicious,
        "risk_contribution": 80 if is_suspicious else (20 if homoglyphs_found else 0)
    }


def nlp_lexical_analysis(url):
    """Tokenize and analyze URL using lexical patterns."""
    parsed = urlparse(normalize(url))

    # Tokenize the URL path and query
    path = parsed.path + "?" + parsed.query if parsed.query else parsed.path
    # Split on common delimiters
    tokens = re.split(r'[/\-_\.?&=#+%]', path)
    tokens = [t.lower() for t in tokens if t and len(t) > 1]

    # Score tokens against threat lexicon
    threat_tokens = {"high": [], "medium": [], "low": []}
    for token in tokens:
        for level, words in THREAT_LEXICON.items():
            for word in words:
                if word in token:
                    threat_tokens[level].append(token)
                    break

    # Calculate risk
    risk = (len(threat_tokens["high"]) * 30 +
            len(threat_tokens["medium"]) * 15 +
            len(threat_tokens["low"]) * 5)

    return {
        "total_tokens": len(tokens),
        "tokens": tokens[:20],  # Cap at 20 for response size
        "threat_tokens": threat_tokens,
        "risk_contribution": min(risk, 100)
    }


def nlp_path_analysis(url):
    """Analyze URL path depth, parameters, and structural anomalies."""
    parsed = urlparse(normalize(url))
    path = parsed.path
    query = parsed.query

    # Path analysis
    path_segments = [s for s in path.split('/') if s]
    path_depth = len(path_segments)

    # Query parameter analysis
    params = parse_qs(query) if query else {}
    param_count = len(params)

    # Suspicious patterns
    has_double_extension = bool(re.search(r'\.\w+\.\w+$', path))
    has_encoded_chars = '%' in url
    has_data_exfil_pattern = bool(re.search(r'(base64|eval|exec|script|cmd|shell)', url.lower()))
    excessive_params = param_count > 5

    # Calculate anomaly score
    anomalies = []
    if path_depth > 4:
        anomalies.append("deep_path_structure")
    if has_double_extension:
        anomalies.append("double_file_extension")
    if has_encoded_chars:
        anomalies.append("url_encoded_characters")
    if has_data_exfil_pattern:
        anomalies.append("suspicious_code_pattern")
    if excessive_params:
        anomalies.append("excessive_parameters")

    risk = len(anomalies) * 20
    return {
        "path_depth": path_depth,
        "param_count": param_count,
        "anomalies": anomalies,
        "has_double_extension": has_double_extension,
        "has_encoded_chars": has_encoded_chars,
        "risk_contribution": min(risk, 100)
    }


def nlp_entropy_analysis(url):
    """Advanced entropy and character distribution analysis."""
    parsed = urlparse(normalize(url))
    domain = parsed.netloc
    path = parsed.path

    # Character class distribution
    char_classes = {
        "lowercase": len(re.findall(r'[a-z]', url)),
        "uppercase": len(re.findall(r'[A-Z]', url)),
        "digits": len(re.findall(r'[0-9]', url)),
        "special": len(re.findall(r'[^a-zA-Z0-9]', url))
    }

    total_chars = len(url)
    ratios = {k: round(v / total_chars, 3) if total_chars else 0
              for k, v in char_classes.items()}

    # Domain entropy (higher = more random = more suspicious)
    domain_entropy = entropy(domain) if domain else 0

    # Consecutive consonant detection (random strings have many)
    consonant_runs = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', domain.lower())

    # Digit ratio in domain (legitimate domains rarely have many digits)
    domain_digits = sum(c.isdigit() for c in domain)
    domain_digit_ratio = domain_digits / len(domain) if domain else 0

    is_suspicious = (domain_entropy > 4.0 or
                     len(consonant_runs) > 0 or
                     domain_digit_ratio > 0.3)

    return {
        "url_entropy": round(entropy(url), 4),
        "domain_entropy": round(domain_entropy, 4),
        "char_distribution": ratios,
        "consecutive_consonant_runs": consonant_runs,
        "domain_digit_ratio": round(domain_digit_ratio, 3),
        "is_random_looking": is_suspicious,
        "risk_contribution": 40 if is_suspicious else 0
    }


def perform_nlp_analysis(url):
    """Run the full NLP analysis pipeline on a URL."""
    ngram = nlp_ngram_analysis(url)
    homoglyph = nlp_homoglyph_detection(url)
    lexical = nlp_lexical_analysis(url)
    path = nlp_path_analysis(url)
    entropy_result = nlp_entropy_analysis(url)

    # Overall NLP risk score (weighted average)
    total_risk = (
        ngram["risk_contribution"] * 0.25 +
        homoglyph["risk_contribution"] * 0.30 +
        lexical["risk_contribution"] * 0.20 +
        path["risk_contribution"] * 0.10 +
        entropy_result["risk_contribution"] * 0.15
    )

    # Generate human-readable summary
    findings = []
    if ngram["ngram_count"] > 0:
        findings.append(f"Contains {ngram['ngram_count']} suspicious keyword pattern(s): {', '.join(ngram['suspicious_ngrams'][:5])}")
    if homoglyph["is_typosquatting"]:
        findings.append(f"Possible typosquatting of '{homoglyph['suspected_impersonation']}' using look-alike characters")
    if lexical["threat_tokens"]["high"]:
        findings.append(f"High-risk terms detected in URL structure")
    if path["anomalies"]:
        findings.append(f"Structural anomalies: {', '.join(path['anomalies'])}")
    if entropy_result["is_random_looking"]:
        findings.append("Domain appears randomly generated (high entropy)")

    if not findings:
        findings.append("No suspicious NLP patterns detected")

    return {
        "nlp_risk_score": round(total_risk, 1),
        "summary": findings,
        "details": {
            "ngram_analysis": ngram,
            "homoglyph_detection": homoglyph,
            "lexical_analysis": lexical,
            "path_analysis": path,
            "entropy_analysis": entropy_result
        }
    }


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


# -------- QR REQUEST MODEL --------

class QrScanRequest(BaseModel):
    """Request body for QR code scanning. Frontend decodes the QR and sends the URL."""
    url: str
    qr_data_raw: str = None


# -------- CORE ANALYSIS FUNCTION --------

def analyze_url(url, scan_type="url_scan"):
    """Core URL analysis logic used by both /check and /check-qr endpoints."""
    url_norm = normalize(url)
    domain = urlparse(url_norm).netloc.lower()
    domain_clean = strip_www(domain)

    # ⭐ HARD TRUST OVERRIDE
    if domain_clean in trusted_domains:
        result = {
            "url": url,
            "domain": domain,
            "threat_score": 0,
            "threat_label": "SAFE",
            "prediction": "SAFE",
            "confidence": 1.0,
            "reason": "Trusted domain",
            "scan_type": scan_type,
            "explanation": [{"feature": "trusted_domain", "impact": 0, "value": 1, "direction": "safe"}],
            "nlp_analysis": {
                "nlp_risk_score": 0,
                "summary": ["Trusted domain — NLP analysis not required"],
                "details": {}
            }
        }

        log_scan(
            url=url, domain=domain, threat_score=0,
            threat_label="SAFE", prediction="SAFE", confidence=1.0,
            explanation=[{"feature": "trusted_domain"}],
            scan_type=scan_type
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

    # SHAP explanation (XAI)
    explanation = get_shap_explanation(df)
    if platform:
        explanation.insert(0, {
            "feature": "trusted_platform",
            "impact": -0.5,
            "value": 1,
            "direction": "safe",
            "note": f"Hosted on {platform}"
        })

    # NLP Analysis
    nlp_result = perform_nlp_analysis(url)

    result = {
        "url": url,
        "domain": domain,
        "threat_score": threat_score,
        "threat_label": threat_label,
        "prediction": prediction,
        "confidence": round(confidence, 3),
        "scan_type": scan_type,
        "features": features_dict,
        "explanation": explanation,
        "nlp_analysis": nlp_result
    }

    # Log to database
    log_scan(
        url=url, domain=domain, threat_score=threat_score,
        threat_label=threat_label, prediction=prediction,
        confidence=confidence, features=features_dict,
        explanation=explanation, scan_type=scan_type
    )

    return result


# -------- ROUTES --------

@app.get("/")
def home():
    return {
        "service": "AI-Powered Web Threat Detection API",
        "version": "3.0",
        "endpoints": ["/check", "/check-qr", "/history", "/stats", "/model-info"],
        "capabilities": ["url_scanning", "qr_code_scanning", "nlp_analysis", "xai_shap"]
    }


@app.post("/check")
def check_url(url: str):
    """Analyze a URL for phishing/scam threats with NLP analysis."""
    return analyze_url(url, scan_type="url_scan")


@app.post("/check-qr")
def check_qr(request: QrScanRequest):
    """Analyze a URL decoded from a QR code for threats.
    
    The QR code is decoded client-side using jsQR. The frontend sends
    the extracted URL to this endpoint for ML + NLP analysis.
    """
    qr_data = request.url.strip()
    
    if not qr_data:
        return {"error": "No URL provided from QR code"}

    # Check if the decoded data looks like a URL
    if not (qr_data.startswith("http") or "." in qr_data):
        return {
            "qr_data": qr_data,
            "is_url": False,
            "message": "QR code contains non-URL data"
        }

    # Analyze the URL
    result = analyze_url(qr_data, scan_type="qr_scan")
    result["qr_data_raw"] = request.qr_data_raw or qr_data

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
        "qr_scanning_available": True,
        "nlp_analysis_available": True,
        "capabilities": {
            "ml_models": ["Random Forest", "XGBoost"],
            "xai": "SHAP TreeExplainer",
            "nlp_techniques": [
                "Character N-gram Analysis",
                "Homoglyph/Typosquatting Detection",
                "Lexical Tokenization & Threat Scoring",
                "URL Path & Parameter Analysis",
                "Entropy & Character Distribution Analysis"
            ],
            "input_types": ["URL Text Input", "QR Code Scan (Camera + Image Upload)"]
        }
    }

    if os.path.exists(EVAL_RESULTS_PATH):
        with open(EVAL_RESULTS_PATH) as f:
            info["evaluation"] = json.load(f)

    return info