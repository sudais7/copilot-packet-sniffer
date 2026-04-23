"""
tests/test_sniffer.py
Unit tests for sniffer.py helper functions.
Author: Sudais Mohamed | CTEC 450

These tests cover all pure-Python logic (no Scapy import required):
  - mask_ip()        : partial IP address masking
  - redact()         : regex-based sensitive data removal
  - safe_decode()    : safe UTF-8 byte decoding with redaction
  - parse_http()     : HTTP request-line and host extraction
"""

import re
import sys
import unittest

# ── Inline copies of the functions under test ────────────────────────────────
# We copy them here so the test suite runs without Scapy being installed.
# This mirrors exactly what is in sniffer.py.

EMAIL_RE     = re.compile(r"\b[\w\.-]+@[\w\.-]+\.\w+\b")
AUTH_RE      = re.compile(r"(?im)^authorization:\s*.*$")
COOKIE_RE    = re.compile(r"(?im)^(cookie|set-cookie):\s*.*$")
QS_SECRET_RE = re.compile(r"(?i)(password|passwd|token|session)=([^&\s]+)")


def mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3] + ["xxx"])
    return ip


def redact(text: str) -> str:
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = AUTH_RE.sub("Authorization: [REDACTED]", text)
    text = COOKIE_RE.sub(lambda m: f"{m.group(1)}: [REDACTED]", text)
    text = QS_SECRET_RE.sub(r"\1=[REDACTED]", text)
    return text


def safe_decode(b: bytes, limit: int = 400) -> str:
    return redact(b[:limit].decode("utf-8", errors="ignore"))


def parse_http(payload: bytes):
    s = safe_decode(payload, limit=800)
    if not (s.startswith("GET ")  or s.startswith("POST ") or
            s.startswith("PUT ")  or s.startswith("DELETE ") or
            s.startswith("HEAD ")):
        return None
    lines = s.splitlines()
    req   = lines[0].split()
    method = req[0] if len(req) > 0 else "UNKNOWN"
    path   = req[1] if len(req) > 1 else "UNKNOWN"
    host   = "UNKNOWN"
    for line in lines[1:40]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return {"method": method, "host": redact(host), "path": redact(path)}


# ── Test cases ────────────────────────────────────────────────────────────────

class TestMaskIp(unittest.TestCase):
    """mask_ip() should replace the last octet with 'xxx'."""

    def test_standard_ipv4(self):
        self.assertEqual(mask_ip("192.168.1.100"), "192.168.1.xxx")

    def test_different_subnet(self):
        self.assertEqual(mask_ip("10.0.0.5"), "10.0.0.xxx")

    def test_public_ip(self):
        self.assertEqual(mask_ip("8.8.8.8"), "8.8.8.xxx")

    def test_already_masked(self):
        # Passing a non-IPv4 string should return it unchanged
        self.assertEqual(mask_ip("not-an-ip"), "not-an-ip")

    def test_preserves_first_three_octets(self):
        result = mask_ip("172.16.254.1")
        self.assertTrue(result.startswith("172.16.254."))
        self.assertTrue(result.endswith(".xxx"))


class TestRedact(unittest.TestCase):
    """redact() should scrub emails, auth headers, cookies, and QS secrets."""

    # ── Email redaction ──────────────────────────────────────────────────────
    def test_email_replaced(self):
        result = redact("Contact us at admin@example.com for support.")
        self.assertNotIn("admin@example.com", result)
        self.assertIn("[REDACTED_EMAIL]", result)

    def test_multiple_emails_replaced(self):
        text   = "From: alice@test.org To: bob@company.net"
        result = redact(text)
        self.assertNotIn("alice@test.org", result)
        self.assertNotIn("bob@company.net", result)
        self.assertEqual(result.count("[REDACTED_EMAIL]"), 2)

    def test_no_false_positive_on_plain_text(self):
        text = "Hello world, no emails here."
        self.assertEqual(redact(text), text)

    # ── Authorization header ─────────────────────────────────────────────────
    def test_authorization_header_redacted(self):
        text   = "Authorization: Bearer supersecrettoken123\r\nHost: example.com"
        result = redact(text)
        self.assertNotIn("supersecrettoken123", result)
        self.assertIn("Authorization: [REDACTED]", result)

    def test_authorization_case_insensitive(self):
        text   = "AUTHORIZATION: Basic dXNlcjpwYXNz"
        result = redact(text)
        self.assertNotIn("dXNlcjpwYXNz", result)

    # ── Cookie / Set-Cookie headers ──────────────────────────────────────────
    def test_cookie_header_redacted(self):
        text   = "Cookie: session=abc123; path=/"
        result = redact(text)
        self.assertNotIn("abc123", result)
        self.assertIn("[REDACTED]", result)

    def test_set_cookie_header_redacted(self):
        text   = "Set-Cookie: auth=xyz789; HttpOnly"
        result = redact(text)
        self.assertNotIn("xyz789", result)

    # ── Query-string secrets ─────────────────────────────────────────────────
    def test_password_in_qs_redacted(self):
        text   = "POST /login?password=hunter2&user=alice HTTP/1.1"
        result = redact(text)
        self.assertNotIn("hunter2", result)
        self.assertIn("password=[REDACTED]", result)

    def test_token_in_qs_redacted(self):
        text   = "GET /api?token=mySecretToken HTTP/1.1"
        result = redact(text)
        self.assertNotIn("mySecretToken", result)
        self.assertIn("token=[REDACTED]", result)

    def test_session_in_qs_redacted(self):
        text   = "/dashboard?session=s3cR3t&theme=dark"
        result = redact(text)
        self.assertNotIn("s3cR3t", result)

    def test_passwd_variant_redacted(self):
        text   = "?passwd=abc&user=bob"
        result = redact(text)
        self.assertNotIn("abc", result)
        self.assertIn("passwd=[REDACTED]", result)

    # ── No-op cases ──────────────────────────────────────────────────────────
    def test_clean_text_unchanged(self):
        text = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n"
        self.assertEqual(redact(text), text)


class TestSafeDecode(unittest.TestCase):
    """safe_decode() should decode bytes safely and apply redaction."""

    def test_basic_utf8_decode(self):
        b      = b"Hello, world!"
        result = safe_decode(b)
        self.assertEqual(result, "Hello, world!")

    def test_byte_limit_respected(self):
        b      = b"A" * 500
        result = safe_decode(b, limit=10)
        self.assertEqual(result, "A" * 10)

    def test_invalid_bytes_ignored(self):
        # Should not raise; invalid bytes are replaced with ""
        b      = b"Valid text \xff\xfe more text"
        result = safe_decode(b)
        self.assertIn("Valid text", result)
        self.assertIn("more text", result)

    def test_redaction_applied_after_decode(self):
        b      = b"user@example.com logged in"
        result = safe_decode(b)
        self.assertNotIn("user@example.com", result)
        self.assertIn("[REDACTED_EMAIL]", result)

    def test_default_limit_is_400(self):
        b      = b"X" * 500
        result = safe_decode(b)  # default limit=400
        self.assertEqual(len(result), 400)


class TestParseHttp(unittest.TestCase):
    """parse_http() should extract method, host, and path from HTTP payloads."""

    def _make(self, lines):
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    # ── Happy-path parsing ───────────────────────────────────────────────────
    def test_get_request_parsed(self):
        payload = self._make([
            "GET /index.html HTTP/1.1",
            "Host: www.example.com",
        ])
        result = parse_http(payload)
        self.assertIsNotNone(result)
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["host"],   "www.example.com")
        self.assertEqual(result["path"],   "/index.html")

    def test_post_request_parsed(self):
        payload = self._make([
            "POST /submit HTTP/1.1",
            "Host: api.example.com",
            "Content-Type: application/json",
        ])
        result = parse_http(payload)
        self.assertEqual(result["method"], "POST")
        self.assertEqual(result["path"],   "/submit")

    def test_put_request_parsed(self):
        payload = self._make(["PUT /resource/1 HTTP/1.1", "Host: example.com"])
        result  = parse_http(payload)
        self.assertEqual(result["method"], "PUT")

    def test_delete_request_parsed(self):
        payload = self._make(["DELETE /item/5 HTTP/1.1", "Host: example.com"])
        result  = parse_http(payload)
        self.assertEqual(result["method"], "DELETE")

    def test_head_request_parsed(self):
        payload = self._make(["HEAD / HTTP/1.1", "Host: example.com"])
        result  = parse_http(payload)
        self.assertEqual(result["method"], "HEAD")

    # ── Missing / unknown host ───────────────────────────────────────────────
    def test_missing_host_returns_unknown(self):
        payload = b"GET /path HTTP/1.1\r\n\r\n"
        result  = parse_http(payload)
        self.assertEqual(result["host"], "UNKNOWN")

    # ── Redaction applied inside HTTP fields ─────────────────────────────────
    def test_password_in_path_redacted(self):
        payload = self._make([
            "GET /login?password=secret123 HTTP/1.1",
            "Host: secure.example.com",
        ])
        result = parse_http(payload)
        self.assertNotIn("secret123", result["path"])
        self.assertIn("password=[REDACTED]", result["path"])

    def test_email_in_path_redacted(self):
        payload = self._make([
            "GET /user?email=test@test.com HTTP/1.1",
            "Host: example.com",
        ])
        result = parse_http(payload)
        self.assertNotIn("test@test.com", result["path"])

    # ── Non-HTTP payloads return None ────────────────────────────────────────
    def test_non_http_returns_none(self):
        self.assertIsNone(parse_http(b"\x00\x01binary data"))

    def test_ssh_banner_returns_none(self):
        self.assertIsNone(parse_http(b"SSH-2.0-OpenSSH_8.9"))

    def test_empty_bytes_returns_none(self):
        self.assertIsNone(parse_http(b""))

    def test_dns_payload_returns_none(self):
        self.assertIsNone(parse_http(b"\x00\x01\x00\x00\x00\x01"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
