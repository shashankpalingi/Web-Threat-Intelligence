import pandas as pd
import re
import math
from urllib.parse import urlparse
import tldextract

# -------- LOAD RAW DATASET --------
data = pd.read_csv("../data/reduced_final_data.csv")

# Ensure correct column names
data.columns = data.columns.str.strip().str.lower()

print(f"📊 Dataset loaded: {len(data)} rows")
print(f"   Label distribution:\n{data['label'].value_counts().to_string()}")

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

keywords = [
    "login","verify","secure","update",
    "account","bank","confirm","password"
]

suspicious_tlds = ["xyz","top","ru","tk","cf","ml"]

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


# ⭐ BRAND ABUSE (fixed logic)
def brand_abuse(url):
    domain = urlparse(url).netloc.lower()

    for b in brands:
        if b in domain:
            if domain.endswith(b + ".com"):
                return 0  # official site
            return 1      # impersonation

    return 0


# ⭐ TRUSTED DOMAIN CHECK
def trusted_domain(url):
    domain = urlparse(url).netloc.lower()
    return 1 if domain in trusted_domains else 0


# -------- EXTRACT FEATURES --------

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
        trusted_domain(url)
    ]


print("⚡ Preprocessing...")

features = data["url"].apply(extract)

X = pd.DataFrame(features.tolist(), columns=[
    "length","dot_count","hyphen_count","digit_count",
    "at_symbol","ssl_flag","ip_flag","subdomain_count",
    "suspicious_tld","keyword_score","entropy",
    "brand_abuse","trusted_domain"
])

X["label"] = data["label"]

X.to_csv("processed_dataset.csv", index=False)

print(f"✅ Preprocessing complete! Saved {len(X)} rows to processed_dataset.csv")