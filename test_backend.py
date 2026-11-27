"""
Milestone 4 - test suite for the banking backend.

Each test has a one-line docstring in the form:  "What is tested | Expected result"
run_tests.py turns these into the test-case / result table (TEST_REPORT.md).

Categories:  UnitTests -> ApiTests (integration) -> SecurityTests -> ConcurrencyTests (stress)
"""
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app as bank  # noqa: E402

PERF = {}   # numbers collected during stress tests, printed in the report


def H(token):
    return {"Authorization": "Bearer " + token}


class BankCase(unittest.TestCase):
    """Fresh temporary database for every test."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "test.db")
        bank.app.config["DB_PATH"] = self.path
        bank.app.config["DEMO_MODE"] = True
        self.c = bank.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---- helpers ----
    def register(self, name="Ravi Kumar", phone="9876543210", pin="1234", client=None):
        return (client or self.c).post("/api/register", json=dict(name=name, phone=phone, pin=pin))

    def make_user(self, **kw):
        r = self.register(**kw)
        self.assertEqual(r.status_code, 201, r.get_json())
        d = r.get_json()
        return d["acc_no"], d["device_token"]

    def start_login(self, acc, pin="1234", device=None, client=None):
        body = {"acc_no": acc, "pin": pin}
        if device:
            body["device_token"] = device
        return (client or self.c).post("/api/login", json=body)

    def full_login(self, acc, pin="1234", device=None, client=None):
        r = self.start_login(acc, pin, device, client)
        self.assertEqual(r.status_code, 200, r.get_json())
        ch = r.get_json()
        v = (client or self.c).post("/api/verify-otp", json={"challenge_id": ch["challenge_id"], "otp": ch["demo_otp"]})
        self.assertEqual(v.status_code, 200, v.get_json())
        return v.get_json()

    def user_with_session(self, **kw):
        acc, dev = self.make_user(**kw)
        s = self.full_login(acc, kw.get("pin", "1234"), dev)
        return acc, dev, s["token"]

    def post(self, path, token, **json):
        return self.c.post(path, json=json, headers=H(token))

    def balance(self, token):
        return self.c.get("/api/me", headers=H(token)).get_json()["balance"]

    def sql(self, query, params=()):
        conn = sqlite3.connect(self.path)
        try:
            return conn.execute(query, params).fetchall()
        finally:
            conn.close()


# =============================================================================
# 1. UNIT TESTS - single functions, no web server involved
# =============================================================================
class UnitTests(unittest.TestCase):
    def amount_error(self, raw):
        with self.assertRaises(bank.ApiError) as cm:
            bank.parse_amount(raw)
        return cm.exception.code

    def test_01_valid_amounts(self):
        """Parse valid amounts (500, 10.5, int 25, float 0.1) | Converted exactly to paise"""
        self.assertEqual(bank.parse_amount("500"), 50000)
        self.assertEqual(bank.parse_amount("10.5"), 1050)
        self.assertEqual(bank.parse_amount(25), 2500)
        self.assertEqual(bank.parse_amount(0.1), 10)

    def test_02_negative_and_zero(self):
        """Amounts -100, 0, 0.00 | Rejected"""
        for raw in ("-100", "0", "0.00"):
            self.amount_error(raw)

    def test_03_garbage_input(self):
        """Amounts 'abc', '', '1,000', '--5', Arabic digits | Rejected"""
        for raw in ("abc", "", "   ", "1,000", "1 000", "--5", "5-", "\u0661\u0662\u0663"):
            self.amount_error(raw)

    def test_04_nan_inf_exponent(self):
        """Amounts 'nan', 'inf', '1e5', float NaN/inf | Rejected (this crashed the old CLI)"""
        for raw in ("nan", "inf", "-inf", "Infinity", "1e5", "1E3", float("nan"), float("inf"), 1e16):
            self.amount_error(raw)

    def test_05_too_many_decimals(self):
        """Amounts 1.234 and 0.001 | Rejected (max 2 decimal places)"""
        self.amount_error("1.234")
        self.amount_error("0.001")

    def test_06_amount_limit(self):
        """10,00,000 allowed; 10,00,000.01 and 1 crore rejected | Per-transaction cap enforced"""
        self.assertEqual(bank.parse_amount("1000000"), 100000000)
        self.assertEqual(self.amount_error("1000000.01"), "AMOUNT_TOO_LARGE")
        self.assertEqual(self.amount_error("10000000"), "AMOUNT_TOO_LARGE")

    def test_07_wrong_types(self):
        """Amount given as None, True, list, dict | Rejected"""
        for raw in (None, True, [], {}, [5]):
            self.amount_error(raw)

    def test_08_pin_hashing(self):
        """Hash a PIN with same/different salt | Deterministic per salt, never equals the plain PIN"""
        s1, s2 = b"a" * 16, b"b" * 16
        self.assertEqual(bank.hash_pin("1234", s1), bank.hash_pin("1234", s1))
        self.assertNotEqual(bank.hash_pin("1234", s1), bank.hash_pin("1234", s2))
        self.assertNotEqual(bank.hash_pin("1234", s1), bank.hash_pin("1235", s1))
        self.assertNotIn(b"1234", bank.hash_pin("1234", s1))

    def test_09_name_rules(self):
        """Names: valid English/Hindi accepted; '<script>', 'A', digits rejected | Validation correct"""
        for ok in ("Ravi Kumar", "Abhishek Singh Rathore", "O'Brien-Smith Jr.", "\u0905\u092d\u093f\u0928\u0935 \u0936\u0930\u094d\u092e\u093e"):
            self.assertEqual(bank.check_name(ok), ok)
        for bad in ("<script>alert(1)</script>", "A", "", "12345", "Ravi<b>", "   ", None, 42, "x" * 61):
            with self.assertRaises(ValueError):
                bank.check_name(bad)

    def test_10_phone_and_pin_rules(self):
        """Phone must be 10 digits starting 6-9; PIN exactly 4 digits | Others rejected"""
        self.assertEqual(bank.check_phone("9876543210"), "9876543210")
        for bad in ("5876543210", "987654321", "98765432101", "abcdefghij", "", None):
            with self.assertRaises(ValueError):
                bank.check_phone(bad)
        self.assertEqual(bank.check_pin("0007"), "0007")
        for bad in ("123", "12345", "abcd", "12 4", "", None, 1234):
            with self.assertRaises(ValueError):
                bank.check_pin(bad)

    def test_11_formatting(self):
        """Format paise as money and mask phone numbers | 0.05, 1000.50, -300.50, XXXXXX3210"""
        self.assertEqual(bank.fmt_paise(0), "0.00")
        self.assertEqual(bank.fmt_paise(5), "0.05")
        self.assertEqual(bank.fmt_paise(100050), "1000.50")
        self.assertEqual(bank.fmt_paise(-30050), "-300.50")
        self.assertEqual(bank.mask_phone("9876543210"), "XXXXXX3210")


# =============================================================================
# 2. API / INTEGRATION TESTS - full flows through the web API and database
# =============================================================================
class ApiTests(BankCase):
    def test_01_register(self):
        """Register two accounts | 201, account numbers 1001 and 1002, device token issued"""
        r = self.register()
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["acc_no"], 1001)
        self.assertTrue(r.get_json()["device_token"])
        self.assertEqual(self.register(name="Asha Rao").get_json()["acc_no"], 1002)

    def test_02_register_validation(self):
        """Register with bad name/phone/PIN, non-JSON, JSON list | All rejected with 400"""
        bad = [dict(name="", phone="9876543210", pin="1234"), dict(name="Ravi", phone="123", pin="1234"),
               dict(name="Ravi", phone="9876543210", pin="12"), dict(phone="9876543210", pin="1234")]
        for body in bad:
            self.assertEqual(self.c.post("/api/register", json=body).status_code, 400, body)
        self.assertEqual(self.c.post("/api/register", data="not json", content_type="application/json").status_code, 400)
        self.assertEqual(self.c.post("/api/register", json=[1, 2]).status_code, 400)

    def test_03_full_login_flow(self):
        """Register -> login (PIN) -> verify OTP -> /api/me | Session issued, trusted device, balance 0.00"""
        acc, dev, tok = self.user_with_session()
        me = self.c.get("/api/me", headers=H(tok)).get_json()
        self.assertEqual((me["acc_no"], me["name"], me["balance"], me["trusted"]), (acc, "Ravi Kumar", "0.00", True))

    def test_04_no_account_enumeration(self):
        """Wrong PIN vs non-existent account | Same 401 message for both"""
        acc, _ = self.make_user()
        a = self.start_login(acc, "9999")
        b = self.start_login(5555)
        self.assertEqual((a.status_code, b.status_code), (401, 401))
        self.assertEqual(a.get_json()["message"], b.get_json()["message"])

    def test_05_wrong_otp_then_right(self):
        """Wrong OTP once, then correct OTP | First rejected (OTP_WRONG), second accepted"""
        acc, _ = self.make_user()
        ch = self.start_login(acc).get_json()
        bad = "000000" if ch["demo_otp"] != "000000" else "111111"
        r = self.c.post("/api/verify-otp", json={"challenge_id": ch["challenge_id"], "otp": bad})
        self.assertEqual((r.status_code, r.get_json()["code"]), (400, "OTP_WRONG"))
        r = self.c.post("/api/verify-otp", json={"challenge_id": ch["challenge_id"], "otp": ch["demo_otp"]})
        self.assertEqual(r.status_code, 200)

    def test_06_otp_brute_force_burns_code(self):
        """3 wrong OTPs, then the correct one | Code is destroyed after 3 tries"""
        acc, _ = self.make_user()
        ch = self.start_login(acc).get_json()
        bad = "000000" if ch["demo_otp"] != "000000" else "111111"
        codes = [self.c.post("/api/verify-otp", json={"challenge_id": ch["challenge_id"], "otp": bad}).get_json()["code"]
                 for _ in range(3)]
        self.assertEqual(codes, ["OTP_WRONG", "OTP_WRONG", "OTP_LOCKED"])
        r = self.c.post("/api/verify-otp", json={"challenge_id": ch["challenge_id"], "otp": ch["demo_otp"]})
        self.assertEqual(r.status_code, 400)

    def test_07_otp_expiry(self):
        """Use an OTP 400 seconds after it was issued | Rejected as expired"""
        acc, _ = self.make_user()
        ch = self.start_login(acc).get_json()
        with mock.patch.object(bank, "now", lambda: int(time.time()) + 400):
            r = self.c.post("/api/verify-otp", json={"challenge_id": ch["challenge_id"], "otp": ch["demo_otp"]})
        self.assertEqual((r.status_code, r.get_json()["code"]), (400, "OTP_EXPIRED"))

    def test_08_otp_single_use(self):
        """Verify the same OTP twice | Second attempt rejected"""
        acc, _ = self.make_user()
        ch = self.start_login(acc).get_json()
        body = {"challenge_id": ch["challenge_id"], "otp": ch["demo_otp"]}
        self.assertEqual(self.c.post("/api/verify-otp", json=body).status_code, 200)
        self.assertEqual(self.c.post("/api/verify-otp", json=body).status_code, 400)

    def test_09_deposit_withdraw(self):
        """Deposit 1000 then withdraw 300.50 | Balance 1000.00 then 699.50"""
        _, _, tok = self.user_with_session()
        self.assertEqual(self.post("/api/deposit", tok, amount="1000").get_json()["balance"], "1000.00")
        self.assertEqual(self.post("/api/withdraw", tok, amount="300.50").get_json()["balance"], "699.50")

    def test_10_overdraft_blocked(self):
        """Withdraw 100.01 from a 100.00 balance | 400 INSUFFICIENT_FUNDS, balance unchanged"""
        _, _, tok = self.user_with_session()
        self.post("/api/deposit", tok, amount="100")
        r = self.post("/api/withdraw", tok, amount="100.01")
        self.assertEqual((r.status_code, r.get_json()["code"]), (400, "INSUFFICIENT_FUNDS"))
        self.assertEqual(self.balance(tok), "100.00")

    def test_11_withdraw_exact_balance(self):
        """Withdraw exactly the full balance | Allowed, balance becomes 0.00"""
        _, _, tok = self.user_with_session()
        self.post("/api/deposit", tok, amount="42.42")
        self.assertEqual(self.post("/api/withdraw", tok, amount="42.42").get_json()["balance"], "0.00")

    def test_12_no_float_drift(self):
        """Deposit 0.10 three times, withdraw 0.30 | Exactly 0.30 then 0.00 (old CLI left dust)"""
        _, _, tok = self.user_with_session()
        for _ in range(3):
            self.post("/api/deposit", tok, amount="0.10")
        self.assertEqual(self.balance(tok), "0.30")
        self.assertEqual(self.post("/api/withdraw", tok, amount="0.30").get_json()["balance"], "0.00")

    def test_13_transfer(self):
        """Transfer 250 from account A to B | A=750, B=250, both histories updated"""
        a, _, ta = self.user_with_session()
        b, _, tb = self.user_with_session(name="Asha Rao")
        self.post("/api/deposit", ta, amount="1000")
        r = self.post("/api/transfer", ta, to_acc=b, amount="250")
        self.assertEqual(r.get_json()["balance"], "750.00")
        self.assertEqual(self.balance(tb), "250.00")
        self.assertEqual(self.c.get("/api/history", headers=H(ta)).get_json()["items"][0]["amount"], "-250.00")
        self.assertEqual(self.c.get("/api/history", headers=H(tb)).get_json()["items"][0]["amount"], "+250.00")

    def test_14_transfer_errors(self):
        """Transfer to self, missing account, too much, zero | All rejected, balances untouched"""
        a, _, ta = self.user_with_session()
        self.post("/api/deposit", ta, amount="100")
        self.assertEqual(self.post("/api/transfer", ta, to_acc=a, amount="10").status_code, 400)
        self.assertEqual(self.post("/api/transfer", ta, to_acc=9999, amount="10").status_code, 404)
        b, _ = self.make_user(name="Asha Rao")
        self.assertEqual(self.post("/api/transfer", ta, to_acc=b, amount="500").status_code, 400)
        self.assertEqual(self.post("/api/transfer", ta, to_acc=b, amount="0").status_code, 400)
        self.assertEqual(self.balance(ta), "100.00")

    def test_15_history_order(self):
        """Make 3 transactions, read history | Newest first with type, signed amount, balance_after"""
        _, _, tok = self.user_with_session()
        self.post("/api/deposit", tok, amount="100")
        self.post("/api/withdraw", tok, amount="30")
        self.post("/api/deposit", tok, amount="5")
        items = self.c.get("/api/history", headers=H(tok)).get_json()["items"]
        self.assertEqual([(i["type"], i["amount"], i["balance_after"]) for i in items],
                         [("Deposit", "+5.00", "75.00"), ("Withdraw", "-30.00", "70.00"), ("Deposit", "+100.00", "100.00")])

    def test_16_auth_required(self):
        """Call protected endpoints with no/garbage token | 401 everywhere"""
        for method, path in (("get", "/api/me"), ("get", "/api/history"), ("get", "/api/forms"),
                             ("post", "/api/deposit"), ("post", "/api/withdraw"), ("post", "/api/transfer"),
                             ("post", "/api/forms")):
            self.assertEqual(getattr(self.c, method)(path, json={}).status_code, 401, path)
        for hdr in ({"Authorization": "Bearer nonsense"}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer "}):
            self.assertEqual(self.c.get("/api/me", headers=hdr).status_code, 401)

    def test_17_session_expiry(self):
        """Use a session 2000 seconds after login | 401 SESSION_EXPIRED"""
        _, _, tok = self.user_with_session()
        with mock.patch.object(bank, "now", lambda: int(time.time()) + 2000):
            r = self.c.get("/api/me", headers=H(tok))
        self.assertEqual((r.status_code, r.get_json()["code"]), (401, "SESSION_EXPIRED"))

    def test_18_logout(self):
        """Log out, then reuse the old token | Token no longer works"""
        _, _, tok = self.user_with_session()
        self.assertEqual(self.c.post("/api/logout", headers=H(tok)).status_code, 200)
        self.assertEqual(self.c.get("/api/me", headers=H(tok)).status_code, 401)

    def test_19_forms_flow(self):
        """List form types, submit a KYC form, list my requests | 7 types; request saved with status Submitted"""
        _, _, tok = self.user_with_session()
        types = self.c.get("/api/forms/types", headers=H(tok)).get_json()["items"]
        self.assertEqual(len(types), 7)
        r = self.post("/api/forms", tok, type="kyc", fields={"doc_type": "PAN", "doc_number": "ABCDE1234F"})
        self.assertEqual(r.status_code, 201)
        item = self.c.get("/api/forms", headers=H(tok)).get_json()["items"][0]
        self.assertEqual((item["type"], item["status"]), ("KYC update", "Submitted"))
        self.assertEqual(item["details"][1]["value"], "ABCDE1234F")

    def test_20_forms_validation(self):
        """Forms with bad doc number, bad phone, bad choice, unknown type, missing fields | All 400"""
        _, _, tok = self.user_with_session()
        bad = [dict(type="kyc", fields={"doc_type": "PAN", "doc_number": "12"}),
               dict(type="mobile", fields={"new_mobile": "12345"}),
               dict(type="card", fields={"card_action": "Give me free money"}),
               dict(type="nope", fields={}), dict(type="kyc", fields={}), dict(type="kyc"),
               dict(type="kyc", fields="x")]
        for body in bad:
            self.assertEqual(self.post("/api/forms", tok, **body).status_code, 400, body)

    def test_21_data_survives_restart(self):
        """Deposit, 'restart' the app (reopen DB), log in again | Balance and history still there"""
        acc, dev, tok = self.user_with_session()
        self.post("/api/deposit", tok, amount="777.77")
        bank._initialized.clear()
        self.c = bank.app.test_client()
        s = self.full_login(acc, "1234", dev)
        self.assertEqual(self.balance(s["token"]), "777.77")
        self.assertEqual(len(self.c.get("/api/history", headers=H(s["token"])).get_json()["items"]), 1)

    def test_22_json_number_amounts(self):
        """Send amounts as JSON numbers 10 and 10.25 | Accepted exactly"""
        _, _, tok = self.user_with_session()
        self.post("/api/deposit", tok, amount=10)
        self.assertEqual(self.post("/api/deposit", tok, amount=10.25).get_json()["balance"], "20.25")

    def test_23_transaction_limit(self):
        """Deposit above 10,00,000 limit | 400 AMOUNT_TOO_LARGE"""
        _, _, tok = self.user_with_session()
        r = self.post("/api/deposit", tok, amount="1000000.01")
        self.assertEqual((r.status_code, r.get_json()["code"]), (400, "AMOUNT_TOO_LARGE"))

    def test_24_website_served(self):
        """GET / and /static files | Home page, CSS and JS are served"""
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Secure Digital Banking", r.data)
        r.close()
        for f in ("/static/app.js", "/static/style.css"):
            resp = self.c.get(f)
            self.assertEqual(resp.status_code, 200, f)
            resp.close()

    def test_25_json_errors(self):
        """Unknown API route and wrong HTTP method | JSON 404 and 405, not HTML"""
        r = self.c.get("/api/nothing")
        self.assertEqual((r.status_code, r.get_json()["code"]), (404, "NOT_FOUND"))
        r = self.c.get("/api/deposit")
        self.assertEqual((r.status_code, r.get_json()["code"]), (405, "METHOD_NOT_ALLOWED"))


# =============================================================================
# 3. SECURITY TESTS
# =============================================================================
class SecurityTests(BankCase):
    def test_01_pin_lockout(self):
        """3 wrong PINs, then the CORRECT PIN | 401, 401, 423 locked, then still 423"""
        acc, _ = self.make_user()
        codes = [self.start_login(acc, "9999").status_code for _ in range(3)]
        self.assertEqual(codes, [401, 401, 423])
        self.assertEqual(self.start_login(acc, "1234").status_code, 423)

    def test_02_counter_resets(self):
        """2 wrong PINs, 1 correct login, 2 more wrong PINs | Never locked (counter reset by success)"""
        acc, dev = self.make_user()
        self.start_login(acc, "9999"); self.start_login(acc, "9999")
        self.full_login(acc, "1234", dev)
        self.assertEqual([self.start_login(acc, "9999").status_code for _ in range(2)], [401, 401])
        self.assertEqual(self.start_login(acc, "1234").status_code, 200)

    def test_03_admin_unlock(self):
        """Locked account unlocked by bank staff | Login works again"""
        acc, _ = self.make_user()
        for _ in range(3):
            self.start_login(acc, "9999")
        self.assertTrue(bank.admin_unlock(acc))
        self.assertEqual(self.start_login(acc, "1234").status_code, 200)

    def test_04_untrusted_device_blocked(self):
        """Correct account+PIN+OTP from an unrecognized device | Can log in and view, but deposit/withdraw/transfer = 403"""
        acc, dev, ok_tok = self.user_with_session()
        self.post("/api/deposit", ok_tok, amount="500")
        other, _ = self.make_user(name="Asha Rao")
        s = self.full_login(acc, "1234", device=None)          # fraudster: no device token
        self.assertFalse(s["trusted"])
        tok = s["token"]
        self.assertEqual(self.c.get("/api/me", headers=H(tok)).status_code, 200)
        self.assertEqual(self.c.get("/api/history", headers=H(tok)).status_code, 200)
        for path, body in (("/api/deposit", dict(amount="1")), ("/api/withdraw", dict(amount="1")),
                           ("/api/transfer", dict(to_acc=other, amount="1"))):
            r = self.post(path, tok, **body)
            self.assertEqual((r.status_code, r.get_json()["code"]), (403, "UNTRUSTED_DEVICE"), path)
        self.assertEqual(self.balance(ok_tok), "500.00")

    def test_05_wrong_device_token(self):
        """Login with a made-up device token | Treated as untrusted"""
        acc, _ = self.make_user()
        self.assertFalse(self.full_login(acc, "1234", device="forged-token-123")["trusted"])

    def test_06_trusted_device_allowed(self):
        """Login with the real device token | Trusted, transactions allowed"""
        acc, dev = self.make_user()
        s = self.full_login(acc, "1234", dev)
        self.assertTrue(s["trusted"])
        self.assertEqual(self.post("/api/deposit", s["token"], amount="5").status_code, 200)

    def test_07_sensitive_forms_need_trusted_device(self):
        """Untrusted device submits 'change mobile' vs 'change trusted device' | 403 vs 201"""
        acc, _ = self.make_user()
        tok = self.full_login(acc, "1234", device=None)["token"]
        r = self.post("/api/forms", tok, type="mobile", fields={"new_mobile": "9123456780"})
        self.assertEqual((r.status_code, r.get_json()["code"]), (403, "UNTRUSTED_DEVICE"))
        r = self.post("/api/forms", tok, type="device", fields={"reason": "Lost / stolen phone", "alt_contact": "9123456780"})
        self.assertEqual(r.status_code, 201)

    def test_08_admin_device_reset(self):
        """Bank staff reset the trusted device | Old device token stops working; next verified login binds a new device"""
        acc, old_dev = self.make_user()
        self.assertTrue(bank.admin_reset_device(acc))
        s = self.full_login(acc, "1234", device=old_dev)
        self.assertTrue(s["trusted"] and s["device_token"])
        self.assertNotEqual(s["device_token"], old_dev)
        self.assertFalse(self.full_login(acc, "1234", device=old_dev)["trusted"])
        self.assertTrue(self.full_login(acc, "1234", device=s["device_token"])["trusted"])

    def test_09_security_headers(self):
        """Inspect response headers | CSP, nosniff, frame-deny, no-store on API"""
        r = self.c.get("/")
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        r.close()
        self.assertEqual(self.c.get("/api/health").headers["Cache-Control"], "no-store")

    def test_10_sql_injection(self):
        """SQL-injection strings in every input field | Never a 500; tables intact; text stored literally"""
        acc, dev, tok = self.user_with_session()
        before = self.sql("SELECT COUNT(*) FROM accounts")[0][0]
        evil = ["' OR '1'='1", "1; DROP TABLE accounts;--", "\" OR 1=1 --", "1 UNION SELECT * FROM accounts"]
        for e in evil:
            responses = [
                self.c.post("/api/login", json={"acc_no": e, "pin": "1234"}),
                self.c.post("/api/login", json={"acc_no": acc, "pin": e}),
                self.c.post("/api/login", json={"acc_no": acc, "pin": "1234", "device_token": e}),
                self.c.post("/api/verify-otp", json={"challenge_id": e, "otp": "123456"}),
                self.c.post("/api/register", json=dict(name=e, phone="9876543210", pin="1234")),
                self.post("/api/deposit", tok, amount=e),
                self.post("/api/transfer", tok, to_acc=e, amount="1"),
                self.post("/api/forms", tok, type="kyc", fields={"doc_type": e, "doc_number": e}),
            ]
            for r in responses:
                self.assertLess(r.status_code, 500, e)
        stored = "'); DROP TABLE accounts;-- harmless address text"
        r = self.post("/api/forms", tok, type="address", fields={"new_address": stored})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM accounts")[0][0], before)
        self.assertIn(stored, self.sql("SELECT details FROM service_requests")[0][0])

    def test_11_oversized_body(self):
        """Send a 20 KB request body | 413 PAYLOAD_TOO_LARGE as JSON"""
        r = self.c.post("/api/register", data="x" * 20000, content_type="application/json")
        self.assertEqual((r.status_code, r.get_json()["code"]), (413, "PAYLOAD_TOO_LARGE"))

    def test_12_malformed_json(self):
        """Send broken JSON | 400, no crash"""
        r = self.c.post("/api/login", data="{not valid", content_type="application/json")
        self.assertEqual(r.status_code, 400)

    def test_13_xss_payloads_rejected(self):
        """HTML/script in name, address, nominee | Rejected (and frontend renders with textContent)"""
        payloads = ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>']
        for p in payloads:
            self.assertEqual(self.register(name=p).status_code, 400)
        _, _, tok = self.user_with_session()
        r = self.post("/api/forms", tok, type="address", fields={"new_address": "12 Main St <script>alert(1)</script>"})
        self.assertEqual(r.status_code, 400)
        r = self.post("/api/forms", tok, type="nominee", fields={"nominee_name": "<b>x</b>", "relationship": "Parent"})
        self.assertEqual(r.status_code, 400)

    def test_14_secrets_not_stored_in_plaintext(self):
        """Inspect database after register+login | PIN and session token are not stored as-is"""
        acc, dev = self.make_user(pin="7391")
        s = self.full_login(acc, "7391", dev)
        pin_salt, pin_hash, device_hash = self.sql("SELECT pin_salt, pin_hash, device_hash FROM accounts")[0]
        self.assertNotIn(b"7391", pin_hash + pin_salt)
        self.assertNotEqual(device_hash, dev)
        stored = [row[0] for row in self.sql("SELECT token_hash FROM sessions")]
        self.assertNotIn(s["token"], stored)

    def test_15_audit_log(self):
        """Failed logins, lockout, blocked transaction, successful login | Each recorded in audit_log"""
        acc, dev = self.make_user()
        for _ in range(3):
            self.start_login(acc, "9999")
        bank.admin_unlock(acc)
        tok = self.full_login(acc, "1234", device=None)["token"]
        self.post("/api/deposit", tok, amount="5")
        events = {r[0] for r in self.sql("SELECT event FROM audit_log")}
        for needed in ("account_created", "login_failed", "account_locked", "admin_unlock", "login_ok",
                       "blocked_untrusted_device"):
            self.assertIn(needed, events)

    def test_16_phone_never_exposed(self):
        """Read /api/me and login responses | Only the masked phone number is returned"""
        acc, dev = self.make_user()
        r = self.start_login(acc, "1234", dev)
        self.assertNotIn("9876543210", r.get_data(as_text=True))
        tok = self.full_login(acc, "1234", dev)["token"]
        text = self.c.get("/api/me", headers=H(tok)).get_data(as_text=True)
        self.assertNotIn("9876543210", text)
        self.assertIn("XXXXXX3210", text)

    def test_17_database_blocks_negative_balance(self):
        """Try to write a negative balance directly in SQL | Database CHECK constraint refuses"""
        self.make_user()
        conn = sqlite3.connect(self.path)
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE accounts SET balance_paise = -1")
        finally:
            conn.close()


# =============================================================================
# 4. CONCURRENCY & STRESS TESTS
# =============================================================================
class ConcurrencyTests(BankCase):
    def run_parallel(self, fn, args_list, workers=16):
        def job(a):
            return fn(bank.app.test_client(), a)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            return list(ex.map(job, args_list))

    def test_01_parallel_deposits(self):
        """50 deposits of 1.00 sent at the same time | Final balance exactly 50.00, 50 history rows, no errors"""
        _, _, tok = self.user_with_session()
        res = self.run_parallel(lambda c, _: c.post("/api/deposit", json={"amount": "1.00"}, headers=H(tok)).status_code,
                                range(50))
        self.assertEqual(set(res), {200})
        self.assertEqual(self.balance(tok), "50.00")
        self.assertEqual(len(self.c.get("/api/history", headers=H(tok)).get_json()["items"]), 50)

    def test_02_parallel_withdrawals_no_overdraft(self):
        """30 simultaneous withdrawals of 1.00 from a 10.00 balance | Exactly 10 succeed, balance 0.00, never negative"""
        _, _, tok = self.user_with_session()
        self.post("/api/deposit", tok, amount="10")
        res = self.run_parallel(lambda c, _: c.post("/api/withdraw", json={"amount": "1"}, headers=H(tok)).status_code,
                                range(30))
        self.assertEqual(res.count(200), 10)
        self.assertEqual(res.count(400), 20)
        self.assertEqual(self.balance(tok), "0.00")

    def test_03_parallel_opposing_transfers(self):
        """40 simultaneous transfers A->B and B->A (20 each) | Total money conserved, both end at 100.00"""
        a, _, ta = self.user_with_session()
        b, _, tb = self.user_with_session(name="Asha Rao")
        self.post("/api/deposit", ta, amount="100")
        self.post("/api/deposit", tb, amount="100")

        def job(c, i):
            if i % 2 == 0:
                return c.post("/api/transfer", json={"to_acc": b, "amount": "1"}, headers=H(ta)).status_code
            return c.post("/api/transfer", json={"to_acc": a, "amount": "1"}, headers=H(tb)).status_code
        res = self.run_parallel(job, range(40))
        self.assertEqual(set(res), {200})
        self.assertEqual((self.balance(ta), self.balance(tb)), ("100.00", "100.00"))
        total = self.sql("SELECT SUM(balance_paise) FROM accounts")[0][0]
        self.assertEqual(total, 20000)

    def test_04_parallel_registrations(self):
        """20 accounts registered at the same time | 20 unique account numbers, none lost"""
        res = self.run_parallel(lambda c, i: self.register(name=f"User {chr(65 + i % 26)}", client=c).get_json()["acc_no"],
                                range(20), workers=10)
        self.assertEqual(sorted(res), list(range(1001, 1021)))

    def test_05_parallel_pin_guessing_cannot_bypass_lockout(self):
        """30 simultaneous wrong-PIN guesses | Account locks; at most 3 guesses ever evaluated; correct PIN then refused"""
        acc, _ = self.make_user()
        res = self.run_parallel(lambda c, _: self.start_login(acc, "9999", client=c).status_code, range(30))
        self.assertEqual(self.start_login(acc, "1234").status_code, 423)
        failed = self.sql("SELECT COUNT(*) FROM audit_log WHERE event='login_failed'")[0][0]
        self.assertLessEqual(failed, 3)
        self.assertEqual(self.sql("SELECT locked FROM accounts")[0][0], 1)
        self.assertTrue(set(res) <= {401, 423})

    def test_06_sequential_stress(self):
        """300 deposits in a row, then 300 reads | Exact final balance; throughput recorded"""
        _, _, tok = self.user_with_session()
        t0 = time.perf_counter()
        for _ in range(300):
            self.post("/api/deposit", tok, amount="1.01")
        dt_w = time.perf_counter() - t0
        t0 = time.perf_counter()
        for _ in range(300):
            self.c.get("/api/me", headers=H(tok))
        dt_r = time.perf_counter() - t0
        self.assertEqual(self.balance(tok), "303.00")
        PERF["write_ops_per_sec"] = round(300 / dt_w, 1)
        PERF["read_ops_per_sec"] = round(300 / dt_r, 1)
        self.assertLess(dt_w, 60)

    def test_07_mixed_workload_invariant(self):
        """8 users run deposits, withdrawals and transfers in parallel | No server errors; total money equals expected 240.00"""
        users = [self.user_with_session(name=f"User {chr(65 + i)}") for i in range(8)]

        def job(c, idx):
            acc, _, tok = users[idx]
            nxt = users[(idx + 1) % 8][0]
            codes = []
            for _ in range(10):
                codes.append(c.post("/api/deposit", json={"amount": "5"}, headers=H(tok)).status_code)
                codes.append(c.post("/api/withdraw", json={"amount": "2"}, headers=H(tok)).status_code)
                codes.append(c.post("/api/transfer", json={"to_acc": nxt, "amount": "1"}, headers=H(tok)).status_code)
            return codes
        t0 = time.perf_counter()
        res = self.run_parallel(job, range(8), workers=8)
        PERF["mixed_240_ops_seconds"] = round(time.perf_counter() - t0, 2)
        flat = [c for r in res for c in r]
        self.assertTrue(all(c < 500 for c in flat))
        self.assertEqual(self.sql("SELECT SUM(balance_paise) FROM accounts")[0][0], 24000)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM accounts WHERE balance_paise < 0")[0][0], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
