"""End-to-end test of cx_auditor against a local mock of Checkmarx One + IAM."""
import base64
import csv
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cx_auditor  # noqa: E402

TENANT = "acme"
NOW_MS = 1_790_000_000_000  # fixed timestamps; window filtering is server-side for these APIs
USERS = [
    {"id": "u-alice", "username": "alice", "email": "alice@example.com", "enabled": True},
    {"id": "u-bob", "username": "bob", "email": "bob@example.com", "enabled": True},
]
AUDIT_EVENTS = [
    {"eventID": f"e{i}", "eventDate": f"2026-11-0{1 + i % 9}T10:00:00Z", "eventType": "projects.create",
     "auditResource": "projects", "actionType": "create", "actionUserId": "u-alice",
     "ipAddress": "10.0.0.1", "tenantID": "t", "data": {"name": f"p{i}"}}
    for i in range(1500)  # forces two pages at limit=1000
]


def fake_jwt(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{enc({'alg': 'HS256'})}.{enc(claims)}.sig"


class Handler(BaseHTTPRequestHandler):
    calls: list = []

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        assert self.path == f"/auth/realms/{TENANT}/protocol/openid-connect/token"
        assert form["grant_type"] == ["refresh_token"] and form["client_id"] == ["ast-app"]
        self._json({"access_token": "AT", "expires_in": 1800})

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        Handler.calls.append((u.path, q, self.headers.get("Accept")))
        if self.headers.get("Authorization") != "Bearer AT":
            return self._json({"error": "unauthorized"}, 401)
        admin = f"/auth/admin/realms/{TENANT}"
        if u.path == "/api/audit-events":
            off, lim = int(q["offset"]), int(q["limit"])
            return self._json({"events": AUDIT_EVENTS[off:off + lim],
                               "totalFilteredCount": len(AUDIT_EVENTS)})
        if u.path == f"{admin}/users":
            first = int(q.get("first", 0))
            return self._json(USERS[first:first + int(q.get("max", 100))])
        if u.path == f"{admin}/clients":
            return self._json([{"id": "cl-uuid", "clientId": "ast-app"}])
        if u.path == f"{admin}/users/u-alice/offline-sessions/cl-uuid":
            return self._json([{"id": "sess-1", "userId": "u-alice", "ipAddress": "1.2.3.4",
                                "start": NOW_MS - 86_400_000, "lastAccess": NOW_MS}])
        if u.path == f"{admin}/users/u-bob/offline-sessions/cl-uuid":
            return self._json([])
        if u.path.endswith("/consents"):
            return self._json([{"clientId": "ast-app", "createdDate": NOW_MS - 86_400_000,
                                "lastUpdatedDate": NOW_MS,
                                "additionalGrants": [{"key": "Offline Token"}]}]
                              if "u-alice" in u.path else [])
        if u.path == f"{admin}/admin-events":
            return self._json([{"time": NOW_MS, "operationType": "CREATE", "resourceType": "USER",
                                "resourcePath": "users/u-bob",
                                "authDetails": {"userId": "u-alice", "clientId": "ast-app",
                                                "ipAddress": "1.2.3.4"}}])
        if u.path == f"{admin}/events":
            return self._json([
                {"time": NOW_MS, "type": "REFRESH_TOKEN", "clientId": "ast-app", "userId": "u-alice",
                 "sessionId": "sess-1", "ipAddress": "5.6.7.8",
                 "details": {"refresh_token_type": "Offline"}},
                {"time": NOW_MS, "type": "LOGIN", "clientId": "ast-app", "userId": "u-bob",
                 "sessionId": "s-web", "ipAddress": "9.9.9.9", "details": {}},
            ])
        return self._json({"message": "not found"}, 404)


class AuditorTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_derive_endpoints_from_key(self):
        key = fake_jwt({"iss": "https://eu.iam.checkmarx.net/auth/realms/acme"})
        self.assertEqual(cx_auditor.derive_endpoints(key),
                         ("https://eu.iam.checkmarx.net", "acme", "https://eu.ast.checkmarx.net"))

    def test_end_to_end(self):
        Handler.calls.clear()
        out = tempfile.mkdtemp()
        args = cx_auditor.parse_args(["--api-key", "KEY", "--iam-url", self.base, "--base-url", self.base,
                                      "--tenant", TENANT, "--out", out, "--days", "30"])
        self.assertEqual(cx_auditor.run(args), 0)

        def read(name):
            with open(os.path.join(out, name), encoding="utf-8") as fh:
                return list(csv.DictReader(fh))
        audit = read("audit_trail.csv")
        self.assertEqual(len(audit), 1500)
        self.assertEqual(audit[0]["actor_user"], "alice")
        audit_calls = [c for c in Handler.calls if c[0] == "/api/audit-events"]
        self.assertEqual([c[1]["offset"] for c in audit_calls], ["0", "1000"])
        self.assertEqual(audit_calls[0][2], "application/json; version=1.0")

        keys = read("api_keys.csv")
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["created_by_user"], "alice")
        self.assertEqual(keys[0]["last_used_from_ip"], "1.2.3.4")

        usage = read("api_key_usage.csv")
        self.assertEqual(len(usage), 1)
        self.assertEqual(usage[0]["used_by_user"], "alice")
        self.assertEqual(usage[0]["api_key_created_by"], "alice")
        self.assertEqual(usage[0]["ip_address"], "5.6.7.8")

        admin = read("iam_admin_events.csv")
        self.assertEqual(admin[0]["actor_user"], "alice")

        with open(os.path.join(out, "summary.json"), encoding="utf-8") as fh:
            summary = json.load(fh)
        self.assertEqual(summary["per_user"]["alice"]["api_keys_created"], 1)
        self.assertEqual(summary["per_user"]["alice"]["api_key_ips"], ["5.6.7.8"])
        self.assertTrue(all(s["status"] == "ok" for s in summary["sections"].values()))


if __name__ == "__main__":
    unittest.main()
