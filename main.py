from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
from rapidfuzz.distance import Levenshtein
from bs4 import BeautifulSoup
import ipaddress
import re
import email
from email import policy
import sqlite3
import json
import tldextract
from datetime import datetime

# Use tldextract's bundled offline snapshot only — never fetch the public
# suffix list over the network. A security tool shouldn't have a hidden
# outbound network dependency just to parse a domain name.
domain_extractor = tldextract.TLDExtract(suffix_list_urls=())

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------
# DATABASE SETUP
# ---------------------------------------------------------

DB_FILE = "phishguard.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS investigations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            target TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            created_at TEXT,
            details TEXT
        )
    """)

    # These columns were added after the table already existed for some users,
    # so we add them here if missing. If they already exist, SQLite raises an
    # error, which we just ignore.
    for column_def in [
        "ALTER TABLE investigations ADD COLUMN analyst_verdict TEXT",
        "ALTER TABLE investigations ADD COLUMN feedback_reason TEXT",
        "ALTER TABLE investigations ADD COLUMN feedback_at TEXT"
    ]:
        try:
            cursor.execute(column_def)
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()

# Run this once when the app starts, so the table always exists.
init_db()

def save_investigation(investigation_type, target, risk_score, risk_level, details_dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO investigations (type, target, risk_score, risk_level, created_at, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            investigation_type,
            target,
            risk_score,
            risk_level,
            datetime.now().isoformat(),
            json.dumps(details_dict)
        )
    )
    conn.commit()
    conn.close()

def get_recent_investigations(limit=50):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, type, target, risk_score, risk_level, created_at FROM investigations ORDER BY id DESC LIMIT ?",
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]

@app.get("/api/investigations")
def list_investigations():
    return get_recent_investigations()

def delete_investigation(investigation_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
    conn.commit()
    rows_changed = cursor.rowcount
    conn.close()
    return rows_changed

def delete_all_investigations():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM investigations")
    conn.commit()
    conn.close()

@app.delete("/api/investigations/{investigation_id}")
def remove_investigation(investigation_id: int):
    rows_changed = delete_investigation(investigation_id)
    if rows_changed == 0:
        return {"success": False, "error": "No investigation found with that id."}
    return {"success": True}

@app.delete("/api/investigations")
def clear_all_investigations():
    delete_all_investigations()
    return {"success": True}

# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.get("/api/health")
def health_check():
    return {"status": "ok"}

# ---------------------------------------------------------
# URL ANALYSIS
# ---------------------------------------------------------

def is_ip_address(hostname):
    if hostname is None:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

SUSPICIOUS_KEYWORDS = ["login", "verify", "secure", "account", "update", "password", "wallet", "payment"]

def has_suspicious_keywords(url):
    url_lower = url.lower()
    for word in SUSPICIOUS_KEYWORDS:
        if word in url_lower:
            return True
    return False

def has_punycode(hostname):
    if hostname is None:
        return False
    return "xn--" in hostname.lower()

def get_registered_domain(hostname):
    """
    Returns the real, registrable domain — e.g. for 'accounts.paypal.com'
    this returns 'paypal.com', ignoring subdomains. This matters because
    comparing the raw hostname (with subdomains attached) against a brand
    name gives wrong answers: 'www.paypal.com' is NOT close to 'paypal.com'
    by naive edit distance, and 'paypal.evil.com' would be missed entirely
    if we only looked at the end of the string.
    """
    if hostname is None:
        return None
    extracted = domain_extractor(hostname)
    if not extracted.domain:
        return None
    if extracted.suffix:
        return extracted.domain + "." + extracted.suffix
    return extracted.domain

# A larger, more realistic watchlist of commonly impersonated brands.
# Each entry: display name, the real registered domain, and the "core name"
# used for substring/brand-stuffing detection.
KNOWN_BRANDS = [
    {"name": "PayPal", "domain": "paypal.com", "core": "paypal"},
    {"name": "Amazon", "domain": "amazon.com", "core": "amazon"},
    {"name": "Google", "domain": "google.com", "core": "google"},
    {"name": "Microsoft", "domain": "microsoft.com", "core": "microsoft"},
    {"name": "Apple", "domain": "apple.com", "core": "apple"},
    {"name": "Facebook", "domain": "facebook.com", "core": "facebook"},
    {"name": "Instagram", "domain": "instagram.com", "core": "instagram"},
    {"name": "Netflix", "domain": "netflix.com", "core": "netflix"},
    {"name": "LinkedIn", "domain": "linkedin.com", "core": "linkedin"},
    {"name": "Dropbox", "domain": "dropbox.com", "core": "dropbox"},
    {"name": "Adobe", "domain": "adobe.com", "core": "adobe"},
    {"name": "eBay", "domain": "ebay.com", "core": "ebay"},
    {"name": "Chase Bank", "domain": "chase.com", "core": "chase"},
    {"name": "Bank of America", "domain": "bankofamerica.com", "core": "bankofamerica"},
    {"name": "Wells Fargo", "domain": "wellsfargo.com", "core": "wellsfargo"},
    {"name": "American Express", "domain": "americanexpress.com", "core": "amex"},
    {"name": "DHL", "domain": "dhl.com", "core": "dhl"},
    {"name": "FedEx", "domain": "fedex.com", "core": "fedex"},
    {"name": "UPS", "domain": "ups.com", "core": "ups"},
    {"name": "USPS", "domain": "usps.com", "core": "usps"},
    {"name": "Coinbase", "domain": "coinbase.com", "core": "coinbase"},
    {"name": "Binance", "domain": "binance.com", "core": "binance"},
    {"name": "Outlook / Microsoft 365", "domain": "outlook.com", "core": "outlook"},
    {"name": "Steam", "domain": "steampowered.com", "core": "steam"},
    {"name": "Spotify", "domain": "spotify.com", "core": "spotify"},
]

def check_brand_impersonation(hostname):
    """
    Checks a hostname against the brand watchlist two different ways:

    1. Typosquat: the registered domain is a near-miss (1-2 character edit)
       of a real brand's domain, e.g. "paypa1.com" vs "paypal.com".

    2. Brand-stuffing / impersonation: the brand's name is stuffed into a
       domain that is NOT that brand's real domain, e.g.
       "paypal-security-verify.com" or "secure-paypal-login.net".
       This is extremely common in real phishing and edit distance alone
       cannot catch it, since the strings aren't "close" character-by-character.

    Returns a dict {"type": "...", "brand": "...", "domain": "..."} or None.
    """
    registered = get_registered_domain(hostname)
    if registered is None:
        return None

    for brand in KNOWN_BRANDS:
        if registered == brand["domain"]:
            # This is the real, legitimate domain — not impersonation.
            return None

        distance = Levenshtein.distance(registered, brand["domain"])
        if 0 < distance <= 2:
            return {"type": "typosquat", "brand": brand["name"], "domain": brand["domain"]}

        registered_sld = registered.split(".")[0]
        if brand["core"] in registered_sld and registered_sld != brand["core"]:
            return {"type": "impersonation", "brand": brand["name"], "domain": brand["domain"]}

    return None

def calculate_risk_score(hostname_is_ip, has_keywords, is_punycode, brand_hit):
    """
    Weights reflect how strong each signal actually is on its own:

    - Brand impersonation (typosquat or brand-stuffing) is the strongest
      single signal a URL-only analysis can produce — a near-exact
      misspelling or stuffed brand name in a domain someone doesn't own
      is very rarely innocent. It alone should push a URL out of "LOW."
    - IP-based hosting and punycode are strong secondary signals.
    - Suspicious keywords alone are weak — "login" and "verify" appear
      constantly in completely legitimate URLs, so this contributes least.

    Even at maximum (all four signals firing at once), score caps at 100,
    which lands as CRITICAL — appropriate, since that combination is
    essentially never innocent.
    """
    score = 0
    if hostname_is_ip:
        score += 15
    if has_keywords:
        score += 10
    if is_punycode:
        score += 20
    if brand_hit is not None:
        score += 45
    return min(score, 100)

def risk_level(score):
    if score < 25:
        return "LOW"
    elif score < 50:
        return "MEDIUM"
    elif score < 75:
        return "HIGH"
    else:
        return "CRITICAL"

def analyze_single_url(url):
    parsed = urlparse(url)
    ip_flag = is_ip_address(parsed.hostname)
    keyword_flag = has_suspicious_keywords(url)
    punycode_flag = has_punycode(parsed.hostname)
    brand_hit = check_brand_impersonation(parsed.hostname)
    score = calculate_risk_score(ip_flag, keyword_flag, punycode_flag, brand_hit)

    return {
        "url": url,
        "hostname": parsed.hostname,
        "hostname_is_ip": ip_flag,
        "has_suspicious_keywords": keyword_flag,
        "has_punycode": punycode_flag,
        "brand_impersonation_type": brand_hit["type"] if brand_hit else None,
        "brand_impersonation_target": brand_hit["brand"] if brand_hit else None,
        "risk_score": score,
        "risk_level": risk_level(score)
    }

class URLSubmission(BaseModel):
    url: str

@app.post("/api/investigations/url")
def investigate_url(submission: URLSubmission):
    result = analyze_single_url(submission.url)

    save_investigation(
        investigation_type="url",
        target=submission.url,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        details_dict=result
    )

    return result

# ---------------------------------------------------------
# EMAIL ANALYSIS
# ---------------------------------------------------------

def get_reply_to_mismatch(msg):
    from_header = msg['From']
    reply_to_header = msg['Reply-To']
    if reply_to_header is None:
        return False
    from_domain = from_header.split('@')[-1].strip('>').lower() if from_header else ""
    reply_domain = reply_to_header.split('@')[-1].strip('>').lower()
    return from_domain != reply_domain

def extract_auth_results(msg):
    auth_header = msg['Authentication-Results']

    if auth_header is None:
        return {"spf": "none", "dkim": "none", "dmarc": "none"}

    auth_lower = auth_header.lower()

    def find_result(check_name):
        if check_name + "=pass" in auth_lower:
            return "pass"
        elif check_name + "=fail" in auth_lower:
            return "fail"
        elif check_name + "=softfail" in auth_lower:
            return "softfail"
        elif check_name + "=" in auth_lower:
            return "other"
        else:
            return "none"

    return {
        "spf": find_result("spf"),
        "dkim": find_result("dkim"),
        "dmarc": find_result("dmarc")
    }

def has_auth_failure(auth_results):
    return auth_results["spf"] == "fail" or auth_results["dmarc"] == "fail"

URL_PATTERN = re.compile(r'https?://[^\s<>"\']+')

def extract_urls_from_email(msg):
    urls = set()

    plain_body = msg.get_body(preferencelist=('plain',))
    if plain_body:
        text = plain_body.get_content()
        found = URL_PATTERN.findall(text)
        urls.update(found)

    html_body = msg.get_body(preferencelist=('html',))
    if html_body:
        html_content = html_body.get_content()
        soup = BeautifulSoup(html_content, 'html.parser')
        for link in soup.find_all('a', href=True):
            urls.add(link['href'])

    return list(urls)

def calculate_email_risk_score(reply_to_mismatch, auth_failure, url_analyses):
    score = 0
    if reply_to_mismatch:
        score += 15
    if auth_failure:
        score += 25
    if url_analyses:
        worst_url_score = max(u["risk_score"] for u in url_analyses)
        score += worst_url_score
    return min(score, 100)

@app.post("/api/investigations/email")
async def investigate_email(file: UploadFile = File(...)):
    raw_bytes = await file.read()
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    reply_to_mismatch = get_reply_to_mismatch(msg)
    auth_results = extract_auth_results(msg)
    auth_failure = has_auth_failure(auth_results)

    found_urls = extract_urls_from_email(msg)
    url_analyses = [analyze_single_url(u) for u in found_urls]

    score = calculate_email_risk_score(reply_to_mismatch, auth_failure, url_analyses)
    level = risk_level(score)

    result = {
        "filename": file.filename,
        "from": msg['From'],
        "to": msg['To'],
        "reply_to": msg['Reply-To'],
        "subject": msg['Subject'],
        "date": msg['Date'],
        "reply_to_mismatch": reply_to_mismatch,
        "spf": auth_results["spf"],
        "dkim": auth_results["dkim"],
        "dmarc": auth_results["dmarc"],
        "auth_failure": auth_failure,
        "url_count": len(found_urls),
        "urls": url_analyses,
        "risk_score": score,
        "risk_level": level
    }

    save_investigation(
        investigation_type="email",
        target=msg['Subject'] or file.filename,
        risk_score=score,
        risk_level=level,
        details_dict=result
    )

    return result