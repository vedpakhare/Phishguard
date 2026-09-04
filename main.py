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
from datetime import datetime

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
        """
        SELECT id, type, target, risk_score, risk_level, created_at,
               analyst_verdict, feedback_reason, feedback_at
        FROM investigations
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )
    rows = cursor.fetchall()
    conn.close()

    return [dict(row) for row in rows]

@app.get("/api/investigations")
def list_investigations():
    return get_recent_investigations()

VALID_VERDICTS = ["benign", "suspicious", "confirmed_phishing"]

class FeedbackSubmission(BaseModel):
    verdict: str
    reason: str | None = None

def save_feedback(investigation_id, verdict, reason):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """
        UPDATE investigations
        SET analyst_verdict = ?, feedback_reason = ?, feedback_at = ?
        WHERE id = ?
        """,
        (verdict, reason, datetime.now().isoformat(), investigation_id)
    )
    conn.commit()
    rows_changed = cursor.rowcount
    conn.close()
    return rows_changed

@app.post("/api/investigations/{investigation_id}/feedback")
def submit_feedback(investigation_id: int, feedback: FeedbackSubmission):
    if feedback.verdict not in VALID_VERDICTS:
        return {"success": False, "error": "verdict must be one of: " + ", ".join(VALID_VERDICTS)}

    rows_changed = save_feedback(investigation_id, feedback.verdict, feedback.reason)

    if rows_changed == 0:
        return {"success": False, "error": "No investigation found with that id."}

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

KNOWN_BRANDS = ["paypal.com", "amazon.com", "google.com", "microsoft.com", "apple.com", "facebook.com"]

def check_typosquatting(hostname):
    if hostname is None:
        return None
    for brand in KNOWN_BRANDS:
        distance = Levenshtein.distance(hostname, brand)
        if 0 < distance <= 2:
            return brand
    return None

def calculate_risk_score(hostname_is_ip, has_keywords, is_punycode, typosquat_target):
    score = 0
    if hostname_is_ip:
        score += 10
    if has_keywords:
        score += 10
    if is_punycode:
        score += 15
    if typosquat_target is not None:
        score += 25
    return score

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
    typosquat_target = check_typosquatting(parsed.hostname)
    score = calculate_risk_score(ip_flag, keyword_flag, punycode_flag, typosquat_target)

    return {
        "url": url,
        "hostname": parsed.hostname,
        "hostname_is_ip": ip_flag,
        "has_suspicious_keywords": keyword_flag,
        "has_punycode": punycode_flag,
        "typosquat_target": typosquat_target,
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
