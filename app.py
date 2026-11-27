"""
Secure Digital Banking - Backend API (Flask + SQLite)

Design notes
------------
* Money is stored as integer paise, never floats (no rounding drift).
* Every balance change runs inside one SQLite "BEGIN IMMEDIATE" transaction, so
  concurrent requests are serialised and no update is ever lost.
* PINs are hashed with PBKDF2-HMAC-SHA256 + per-user salt + server-side pepper.
* Login is two-step: PIN, then a one-time passcode (OTP).
* Each account is bound to one trusted device (random token held by the client,
  only its hash is stored). Untrusted devices can look but cannot move money.
* PIN lockout reserves an attempt *atomically before* checking the PIN, so
  parallel guesses cannot bypass the 3-attempt limit.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from contextlib import contextmanager
from decimal import Decimal

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def _find_static_dir():
    """Locate the 'static' folder even if it was uploaded as 'Static' (Linux is case-sensitive)."""
    exact = os.path.join(BASE_DIR, "static")
    if os.path.isdir(exact):
        return exact
    try:
        for name in os.listdir(BASE_DIR):
            if name.lower() == "static" and os.path.isdir(os.path.join(BASE_DIR, name)):
                return os.path.join(BASE_DIR, name)
    except OSError:
        pass
    return exact


app = Flask(__name__, static_folder=_find_static_dir(), static_url_path="/static")
app.config.update(
    DB_PATH=os.environ.get("DB_PATH", os.path.join(BASE_DIR, "bank.db")),
    DEMO_MODE=os.environ.get("DEMO_MODE", "1") == "1",  # show OTP on screen (no SMS gateway)
    MAX_CONTENT_LENGTH=16 * 1024,                       # reject request bodies > 16 KB
)

PEPPER = os.environ.get("PIN_PEPPER", "dev-pepper-change-me").encode()
PBKDF2_ITERS = 120_000
MAX_PIN_ATTEMPTS = 3
OTP_TTL = 300            # seconds
OTP_MAX_TRIES = 3
SESSION_TTL = 1800       # seconds
MAX_AMOUNT = Decimal("1000000.00")   # per-transaction cap (10 lakh)
MAX_REQUESTS_PER_ACCOUNT = 50
GENERIC_LOGIN_ERROR = "Invalid account number or PIN."


def now():
    return int(time.time())


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------
class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


@app.errorhandler(ApiError)
def handle_api_error(e):
    return jsonify(ok=False, code=e.code, message=e.message), e.status


@app.errorhandler(HTTPException)
def handle_http_error(e):
    if request.path.startswith("/api/"):
        code = {413: "PAYLOAD_TOO_LARGE", 404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(e.code, "HTTP_ERROR")
        return jsonify(ok=False, code=code, message=e.description), e.code
    return e


@app.errorhandler(Exception)
def handle_unexpected(e):
    app.logger.exception("Unhandled error")
    return jsonify(ok=False, code="SERVER_ERROR", message="Something went wrong on the server."), 500


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts(
  acc_no INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  pin_salt BLOB NOT NULL,
  pin_hash BLOB NOT NULL,
  balance_paise INTEGER NOT NULL DEFAULT 0 CHECK(balance_paise >= 0),
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked INTEGER NOT NULL DEFAULT 0,
  device_hash TEXT,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  acc_no INTEGER NOT NULL REFERENCES accounts(acc_no),
  type TEXT NOT NULL,
  amount_paise INTEGER NOT NULL,
  balance_after_paise INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tx_acc ON transactions(acc_no, id DESC);
CREATE TABLE IF NOT EXISTS service_requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  acc_no INTEGER NOT NULL REFERENCES accounts(acc_no),
  type TEXT NOT NULL,
  details TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Submitted',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_req_acc ON service_requests(acc_no, id DESC);
CREATE TABLE IF NOT EXISTS challenges(
  id TEXT PRIMARY KEY,
  acc_no INTEGER NOT NULL,
  otp_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  tries INTEGER NOT NULL DEFAULT 0,
  device_state TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  acc_no INTEGER NOT NULL,
  trusted INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  acc_no INTEGER,
  event TEXT NOT NULL,
  detail TEXT
);
"""

_initialized = set()
_init_lock = threading.Lock()


def init_db(path=None):
    path = path or app.config["DB_PATH"]
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)
    try:
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.Error:
            pass
        conn.executescript(SCHEMA)
    finally:
        conn.close()
    _initialized.add(path)


def connect():
    path = app.config["DB_PATH"]
    if path not in _initialized:
        with _init_lock:
            if path not in _initialized:
                init_db(path)
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


@contextmanager
def write_tx():
    """One atomic write transaction. BEGIN IMMEDIATE serialises concurrent writers."""
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def read_one(sql, params=()):
    conn = connect()
    try:
        return conn.execute(sql, params).fetchone()
    finally:
        conn.close()


def read_all(sql, params=()):
    conn = connect()
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def audit(db, acc_no, event, detail=""):
    db.execute("INSERT INTO audit_log(ts, acc_no, event, detail) VALUES (?,?,?,?)",
               (now(), acc_no, event, detail[:200]))


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
PHONE_RE = re.compile(r"[6-9][0-9]{9}")
PIN_RE = re.compile(r"[0-9]{4}")
ACC_RE = re.compile(r"[0-9]{4,12}")
AMOUNT_RE = re.compile(r"[0-9]{1,9}(\.[0-9]{1,2})?")
DOC_RE = re.compile(r"[A-Za-z0-9]{6,20}")
OTP_RE = re.compile(r"[0-9]{6}")


def _is_letter(ch):
    return unicodedata.category(ch)[0] in "LM"   # letters + combining marks (e.g. Hindi matras)


def check_name(v, label="Name", lo=2, hi=60):
    if not isinstance(v, str):
        raise ValueError(f"{label} is required.")
    v = " ".join(v.split())
    if not (lo <= len(v) <= hi) or not _is_letter(v[0]) or not all(_is_letter(c) or c in " .'-" for c in v):
        raise ValueError(f"{label} must be {lo}-{hi} characters: letters, spaces, . ' - only.")
    return v


def check_phone(v):
    if not isinstance(v, str) or not PHONE_RE.fullmatch(v.strip()):
        raise ValueError("Enter a valid 10-digit mobile number.")
    return v.strip()


def check_pin(v):
    if not isinstance(v, str) or not PIN_RE.fullmatch(v.strip()):
        raise ValueError("PIN must be exactly 4 digits.")
    return v.strip()


def check_doc_number(v):
    if not isinstance(v, str) or not DOC_RE.fullmatch(v.strip()):
        raise ValueError("Document number must be 6-20 letters or digits.")
    return v.strip()


def text_check(lo, hi, label):
    def _check(v):
        if not isinstance(v, str):
            raise ValueError(f"{label} is required.")
        v = " ".join(v.split())
        if not (lo <= len(v) <= hi) or not v.isprintable() or "<" in v or ">" in v:
            raise ValueError(f"{label} must be {lo}-{hi} characters and cannot contain < or >.")
        return v
    return _check


def choice_check(options, label):
    def _check(v):
        if v not in options:
            raise ValueError(f"Choose a valid option for {label}.")
        return v
    return _check


def validate(fn, value):
    try:
        return fn(value)
    except ValueError as e:
        raise ApiError(400, "VALIDATION", str(e))


def parse_acc(v, label="Account number"):
    s = str(v).strip() if isinstance(v, (str, int)) and not isinstance(v, bool) else ""
    if not ACC_RE.fullmatch(s):
        raise ApiError(400, "VALIDATION", f"Enter a valid {label.lower()}.")
    return int(s)


def parse_amount(raw):
    """Return the amount in paise. Rejects negatives, zero, NaN/inf, exponents, >2 decimals."""
    if raw is None or isinstance(raw, bool):
        raise ApiError(400, "INVALID_AMOUNT", "Enter a valid amount.")
    if isinstance(raw, float):
        s = repr(raw)
    elif isinstance(raw, (int, str)):
        s = str(raw).strip()
    else:
        raise ApiError(400, "INVALID_AMOUNT", "Enter a valid amount.")
    if not AMOUNT_RE.fullmatch(s):
        raise ApiError(400, "INVALID_AMOUNT", "Enter a valid amount (digits, up to 2 decimal places).")
    d = Decimal(s)
    if d <= 0:
        raise ApiError(400, "INVALID_AMOUNT", "Amount must be greater than 0.")
    if d > MAX_AMOUNT:
        raise ApiError(400, "AMOUNT_TOO_LARGE", "Amount exceeds the per-transaction limit of 10,00,000.")
    return int(d * 100)


def fmt_paise(p):
    sign = "-" if p < 0 else ""
    p = abs(p)
    return f"{sign}{p // 100}.{p % 100:02d}"


def mask_phone(p):
    return "XXXXXX" + p[-4:]


def json_body():
    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        raise ApiError(400, "BAD_REQUEST", "Send a valid JSON object.")
    return d


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------
def hash_pin(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), salt + PEPPER, PBKDF2_ITERS)


def sha256_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def hash_otp(otp, challenge_id):
    return sha256_hex(f"{otp}:{challenge_id}")


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------
def current_session(require_trusted=False):
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else ""
    if not token or len(token) > 200:
        raise ApiError(401, "UNAUTHENTICATED", "Please log in.")
    row = read_one("SELECT acc_no, trusted, expires_at FROM sessions WHERE token_hash=?", (sha256_hex(token),))
    if row is None:
        raise ApiError(401, "UNAUTHENTICATED", "Please log in.")
    if row["expires_at"] < now():
        raise ApiError(401, "SESSION_EXPIRED", "Your session expired. Please log in again.")
    if require_trusted and not row["trusted"]:
        with write_tx() as db:
            audit(db, row["acc_no"], "blocked_untrusted_device", request.path)
        raise ApiError(403, "UNTRUSTED_DEVICE",
                       "This device is not your trusted device, so money transactions are blocked.")
    return row


# ---------------------------------------------------------------------------
# Routes - auth
# ---------------------------------------------------------------------------
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/api/health")
def health():
    return jsonify(ok=True, status="running")


@app.post("/api/register")
def register():
    d = json_body()
    name = validate(check_name, d.get("name"))
    phone = validate(check_phone, d.get("phone"))
    pin = validate(check_pin, d.get("pin"))
    salt = secrets.token_bytes(16)
    pin_hash = hash_pin(pin, salt)
    device_token = secrets.token_urlsafe(32)
    with write_tx() as db:
        acc_no = db.execute("SELECT COALESCE(MAX(acc_no), 1000) + 1 FROM accounts").fetchone()[0]
        db.execute(
            "INSERT INTO accounts(acc_no, name, phone, pin_salt, pin_hash, device_hash, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (acc_no, name, phone, salt, pin_hash, sha256_hex(device_token), now()))
        audit(db, acc_no, "account_created")
    return jsonify(ok=True, acc_no=acc_no, device_token=device_token), 201


@app.post("/api/login")
def login():
    d = json_body()
    acc_no = parse_acc(d.get("acc_no"))
    pin = validate(check_pin, d.get("pin"))
    device_token = d.get("device_token")
    if device_token is not None and (not isinstance(device_token, str) or len(device_token) > 100):
        device_token = None

    # Step 1: atomically reserve one PIN attempt BEFORE checking the PIN, so that
    # parallel guesses cannot get around the 3-attempt limit.
    with write_tx() as db:
        acc = db.execute("SELECT * FROM accounts WHERE acc_no=?", (acc_no,)).fetchone()
        if acc is None:
            state = "unknown"
        elif acc["locked"]:
            state = "locked"
        else:
            cur = db.execute(
                "UPDATE accounts SET failed_attempts = failed_attempts + 1 "
                "WHERE acc_no=? AND locked=0 AND failed_attempts < ?", (acc_no, MAX_PIN_ATTEMPTS))
            state = "reserved" if cur.rowcount == 1 else "locked"
            if state == "locked":
                db.execute("UPDATE accounts SET locked=1 WHERE acc_no=?", (acc_no,))

    if state == "unknown":
        hash_pin(pin, b"\x00" * 16)   # equalise timing with the real path
        raise ApiError(401, "INVALID_CREDENTIALS", GENERIC_LOGIN_ERROR)
    if state == "locked":
        raise ApiError(423, "ACCOUNT_LOCKED", "This account is locked after too many wrong PINs. Contact the bank.")

    # Step 2: verify the PIN (expensive hash, done outside any DB lock).
    ok = hmac.compare_digest(hash_pin(pin, acc["pin_salt"]), acc["pin_hash"])

    # Step 3: record the outcome.
    result = {}
    with write_tx() as db:
        if ok:
            cur = db.execute("UPDATE accounts SET failed_attempts=0 WHERE acc_no=? AND locked=0", (acc_no,))
            if cur.rowcount == 0:
                result["locked"] = True
            else:
                if acc["device_hash"] is None:
                    device_state = "bind"
                elif device_token and hmac.compare_digest(sha256_hex(device_token), acc["device_hash"]):
                    device_state = "trusted"
                else:
                    device_state = "untrusted"
                otp = f"{secrets.randbelow(10 ** 6):06d}"
                cid = secrets.token_urlsafe(16)
                db.execute("DELETE FROM challenges WHERE expires_at < ? OR acc_no = ?", (now(), acc_no))
                db.execute(
                    "INSERT INTO challenges(id, acc_no, otp_hash, expires_at, device_state) VALUES (?,?,?,?,?)",
                    (cid, acc_no, hash_otp(otp, cid), now() + OTP_TTL, device_state))
                audit(db, acc_no, "pin_ok", device_state)
                result.update(cid=cid, otp=otp, phone=acc["phone"])
        else:
            db.execute("UPDATE accounts SET locked=1 WHERE acc_no=? AND failed_attempts >= ?",
                       (acc_no, MAX_PIN_ATTEMPTS))
            row = db.execute("SELECT locked FROM accounts WHERE acc_no=?", (acc_no,)).fetchone()
            result["locked"] = bool(row["locked"])
            audit(db, acc_no, "login_failed", "wrong PIN")
            if result["locked"]:
                audit(db, acc_no, "account_locked")

    if result.get("locked"):
        raise ApiError(423, "ACCOUNT_LOCKED", "This account is locked after too many wrong PINs. Contact the bank.")
    if not ok:
        raise ApiError(401, "INVALID_CREDENTIALS", GENERIC_LOGIN_ERROR)

    body = dict(ok=True, challenge_id=result["cid"], phone_masked=mask_phone(result["phone"]), expires_in=OTP_TTL)
    if app.config["DEMO_MODE"]:
        body["demo_otp"] = result["otp"]   # demo only: a real system sends this by SMS
    return jsonify(body)


@app.post("/api/verify-otp")
def verify_otp():
    d = json_body()
    cid, otp = d.get("challenge_id"), d.get("otp")
    if not isinstance(cid, str) or not 1 <= len(cid) <= 64 or not isinstance(otp, str) or not OTP_RE.fullmatch(otp):
        raise ApiError(400, "VALIDATION", "Enter the 6-digit code.")
    result = {}
    with write_tx() as db:
        ch = db.execute("SELECT * FROM challenges WHERE id=?", (cid,)).fetchone()
        if ch is None or ch["expires_at"] < now():
            if ch is not None:
                db.execute("DELETE FROM challenges WHERE id=?", (cid,))
            result["status"] = "expired"
        else:
            cur = db.execute("UPDATE challenges SET tries = tries + 1 WHERE id=? AND tries < ?", (cid, OTP_MAX_TRIES))
            if cur.rowcount == 0:
                db.execute("DELETE FROM challenges WHERE id=?", (cid,))
                result["status"] = "too_many"
            elif not hmac.compare_digest(ch["otp_hash"], hash_otp(otp, cid)):
                if ch["tries"] + 1 >= OTP_MAX_TRIES:
                    db.execute("DELETE FROM challenges WHERE id=?", (cid,))
                    result["status"] = "too_many"
                else:
                    result["status"] = "wrong"
                audit(db, ch["acc_no"], "otp_failed")
            else:
                db.execute("DELETE FROM challenges WHERE id=?", (cid,))
                acc_no = ch["acc_no"]
                trusted, new_device_token = False, None
                if ch["device_state"] == "trusted":
                    trusted = True
                elif ch["device_state"] == "bind":
                    new_device_token = secrets.token_urlsafe(32)
                    cur2 = db.execute("UPDATE accounts SET device_hash=? WHERE acc_no=? AND device_hash IS NULL",
                                      (sha256_hex(new_device_token), acc_no))
                    if cur2.rowcount == 1:
                        trusted = True
                        audit(db, acc_no, "device_bound")
                    else:
                        new_device_token = None
                token = secrets.token_urlsafe(32)
                db.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))
                db.execute("INSERT INTO sessions(token_hash, acc_no, trusted, expires_at) VALUES (?,?,?,?)",
                           (sha256_hex(token), acc_no, int(trusted), now() + SESSION_TTL))
                audit(db, acc_no, "login_ok", "trusted" if trusted else "untrusted")
                result.update(status="ok", token=token, trusted=trusted, device_token=new_device_token)

    st = result["status"]
    if st == "expired":
        raise ApiError(400, "OTP_EXPIRED", "This code has expired. Please log in again.")
    if st == "too_many":
        raise ApiError(429, "OTP_LOCKED", "Too many wrong codes. Please log in again.")
    if st == "wrong":
        raise ApiError(400, "OTP_WRONG", "Incorrect code. Please try again.")
    return jsonify(ok=True, token=result["token"], trusted=result["trusted"], device_token=result["device_token"])


@app.post("/api/logout")
def logout():
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.startswith("Bearer ") else ""
    if token:
        with write_tx() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (sha256_hex(token),))
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    sess = current_session()
    acc = read_one("SELECT acc_no, name, phone, balance_paise FROM accounts WHERE acc_no=?", (sess["acc_no"],))
    return jsonify(ok=True, acc_no=acc["acc_no"], name=acc["name"], phone_masked=mask_phone(acc["phone"]),
                   balance=fmt_paise(acc["balance_paise"]), trusted=bool(sess["trusted"]))


# ---------------------------------------------------------------------------
# Routes - transactions
# ---------------------------------------------------------------------------
def _record(db, acc_no, tx_type, signed_paise):
    bal = db.execute("SELECT balance_paise FROM accounts WHERE acc_no=?", (acc_no,)).fetchone()[0]
    db.execute("INSERT INTO transactions(acc_no, type, amount_paise, balance_after_paise, created_at) "
               "VALUES (?,?,?,?,?)", (acc_no, tx_type, signed_paise, bal, now()))
    return bal


@app.post("/api/deposit")
def deposit():
    sess = current_session(require_trusted=True)
    paise = parse_amount(json_body().get("amount"))
    with write_tx() as db:
        db.execute("UPDATE accounts SET balance_paise = balance_paise + ? WHERE acc_no=?", (paise, sess["acc_no"]))
        bal = _record(db, sess["acc_no"], "Deposit", paise)
    return jsonify(ok=True, balance=fmt_paise(bal))


@app.post("/api/withdraw")
def withdraw():
    sess = current_session(require_trusted=True)
    paise = parse_amount(json_body().get("amount"))
    with write_tx() as db:
        cur = db.execute("UPDATE accounts SET balance_paise = balance_paise - ? WHERE acc_no=? AND balance_paise >= ?",
                         (paise, sess["acc_no"], paise))
        if cur.rowcount == 0:
            raise ApiError(400, "INSUFFICIENT_FUNDS", "Insufficient balance.")
        bal = _record(db, sess["acc_no"], "Withdraw", -paise)
    return jsonify(ok=True, balance=fmt_paise(bal))


@app.post("/api/transfer")
def transfer():
    sess = current_session(require_trusted=True)
    d = json_body()
    target = parse_acc(d.get("to_acc"), "target account number")
    paise = parse_amount(d.get("amount"))
    src = sess["acc_no"]
    if target == src:
        raise ApiError(400, "SAME_ACCOUNT", "You cannot transfer to your own account.")
    with write_tx() as db:
        if db.execute("SELECT 1 FROM accounts WHERE acc_no=?", (target,)).fetchone() is None:
            raise ApiError(404, "NO_SUCH_ACCOUNT", "Target account does not exist.")
        cur = db.execute("UPDATE accounts SET balance_paise = balance_paise - ? WHERE acc_no=? AND balance_paise >= ?",
                         (paise, src, paise))
        if cur.rowcount == 0:
            raise ApiError(400, "INSUFFICIENT_FUNDS", "Insufficient balance.")
        db.execute("UPDATE accounts SET balance_paise = balance_paise + ? WHERE acc_no=?", (paise, target))
        bal = _record(db, src, f"Transfer to #{target}", -paise)
        _record(db, target, f"Transfer from #{src}", paise)
    return jsonify(ok=True, balance=fmt_paise(bal))


@app.get("/api/history")
def history():
    sess = current_session()
    rows = read_all("SELECT type, amount_paise, balance_after_paise, created_at FROM transactions "
                    "WHERE acc_no=? ORDER BY id DESC LIMIT 100", (sess["acc_no"],))
    items = [dict(type=r["type"], amount=("+" if r["amount_paise"] >= 0 else "") + fmt_paise(r["amount_paise"]),
                  balance_after=fmt_paise(r["balance_after_paise"]), created_at=r["created_at"]) for r in rows]
    return jsonify(ok=True, items=items)


# ---------------------------------------------------------------------------
# Routes - paperless service forms
# ---------------------------------------------------------------------------
FORM_SPECS = {
    "mobile": {"label": "Change mobile number", "needs_trusted": True, "fields": [
        {"id": "new_mobile", "label": "New mobile number", "kind": "text", "maxlength": 10,
         "placeholder": "9876543210", "mono": True, "check": check_phone}]},
    "kyc": {"label": "KYC update", "needs_trusted": True, "fields": [
        {"id": "doc_type", "label": "Document type", "kind": "select",
         "options": ["Aadhaar", "PAN", "Passport", "Voter ID"],
         "check": choice_check(["Aadhaar", "PAN", "Passport", "Voter ID"], "document type")},
        {"id": "doc_number", "label": "Document number", "kind": "text", "maxlength": 20,
         "mono": True, "check": check_doc_number}]},
    "address": {"label": "Change address", "needs_trusted": True, "fields": [
        {"id": "new_address", "label": "New address", "kind": "textarea", "maxlength": 200,
         "placeholder": "House no., street, city, PIN code", "check": text_check(10, 200, "Address")}]},
    "card": {"label": "Debit card request", "needs_trusted": True, "fields": [
        {"id": "card_action", "label": "Request type", "kind": "select",
         "options": ["Issue new card", "Block lost / stolen card", "Reissue damaged card"],
         "check": choice_check(["Issue new card", "Block lost / stolen card", "Reissue damaged card"], "request type")}]},
    "nominee": {"label": "Add / update nominee", "needs_trusted": True, "fields": [
        {"id": "nominee_name", "label": "Nominee name", "kind": "text", "maxlength": 60,
         "check": lambda v: check_name(v, "Nominee name")},
        {"id": "relationship", "label": "Relationship", "kind": "text", "maxlength": 30,
         "placeholder": "e.g. Spouse, Parent, Child", "check": lambda v: check_name(v, "Relationship", 2, 30)}]},
    "chequebook": {"label": "Chequebook request", "needs_trusted": True, "fields": [
        {"id": "leaves", "label": "Number of leaves", "kind": "select", "options": ["25", "50", "100"],
         "check": choice_check(["25", "50", "100"], "number of leaves")}]},
    "device": {"label": "Change trusted device", "needs_trusted": False, "fields": [
        {"id": "reason", "label": "Reason", "kind": "select",
         "options": ["Lost / stolen phone", "Bought a new phone", "Other"],
         "check": choice_check(["Lost / stolen phone", "Bought a new phone", "Other"], "reason")},
        {"id": "alt_contact", "label": "Alternate contact number (bank will call to verify)", "kind": "text",
         "maxlength": 10, "mono": True, "check": check_phone}]},
}


@app.get("/api/forms/types")
def form_types():
    current_session()
    out = []
    for fid, spec in FORM_SPECS.items():
        fields = [{k: v for k, v in f.items() if k != "check"} for f in spec["fields"]]
        out.append(dict(id=fid, label=spec["label"], needs_trusted=spec["needs_trusted"], fields=fields))
    return jsonify(ok=True, items=out)


@app.post("/api/forms")
def submit_form():
    sess = current_session()
    d = json_body()
    spec = FORM_SPECS.get(d.get("type")) if isinstance(d.get("type"), str) else None
    if spec is None:
        raise ApiError(400, "VALIDATION", "Unknown form type.")
    if spec["needs_trusted"] and not sess["trusted"]:
        with write_tx() as db:
            audit(db, sess["acc_no"], "blocked_untrusted_device", "form:" + d["type"])
        raise ApiError(403, "UNTRUSTED_DEVICE",
                       "This form can only be submitted from your trusted device.")
    values = d.get("fields")
    if not isinstance(values, dict):
        raise ApiError(400, "VALIDATION", "Fill in the form fields.")
    cleaned = []
    for f in spec["fields"]:
        cleaned.append({"label": f["label"], "value": validate(f["check"], values.get(f["id"]))})
    with write_tx() as db:
        n = db.execute("SELECT COUNT(*) FROM service_requests WHERE acc_no=?", (sess["acc_no"],)).fetchone()[0]
        if n >= MAX_REQUESTS_PER_ACCOUNT:
            raise ApiError(429, "TOO_MANY_REQUESTS", "Too many requests on this account.")
        cur = db.execute("INSERT INTO service_requests(acc_no, type, details, created_at) VALUES (?,?,?,?)",
                         (sess["acc_no"], spec["label"], json.dumps(cleaned), now()))
        audit(db, sess["acc_no"], "form_submitted", d["type"])
    return jsonify(ok=True, id=cur.lastrowid), 201


@app.get("/api/forms")
def list_forms():
    sess = current_session()
    rows = read_all("SELECT id, type, details, status, created_at FROM service_requests "
                    "WHERE acc_no=? ORDER BY id DESC LIMIT 100", (sess["acc_no"],))
    items = [dict(id=r["id"], type=r["type"], details=json.loads(r["details"]), status=r["status"],
                  created_at=r["created_at"]) for r in rows]
    return jsonify(ok=True, items=items)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------
@app.after_request
def add_security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    if request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    return resp


# ---------------------------------------------------------------------------
# Admin helpers (used by admin_tools.py - bank staff only, never exposed over HTTP)
# ---------------------------------------------------------------------------
def admin_unlock(acc_no):
    with write_tx() as db:
        cur = db.execute("UPDATE accounts SET locked=0, failed_attempts=0 WHERE acc_no=?", (acc_no,))
        audit(db, acc_no, "admin_unlock")
    return cur.rowcount == 1


def admin_reset_device(acc_no):
    """After verifying the customer in person/by phone: forget the trusted device."""
    with write_tx() as db:
        cur = db.execute("UPDATE accounts SET device_hash=NULL WHERE acc_no=?", (acc_no,))
        db.execute("DELETE FROM sessions WHERE acc_no=?", (acc_no,))
        audit(db, acc_no, "admin_reset_device")
    return cur.rowcount == 1


def admin_list_requests(status=None):
    sql = "SELECT id, acc_no, type, details, status, created_at FROM service_requests"
    params = ()
    if status:
        sql += " WHERE status=?"
        params = (status,)
    return read_all(sql + " ORDER BY id", params)


def admin_set_request_status(req_id, status):
    with write_tx() as db:
        cur = db.execute("UPDATE service_requests SET status=? WHERE id=?", (status, req_id))
    return cur.rowcount == 1


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
