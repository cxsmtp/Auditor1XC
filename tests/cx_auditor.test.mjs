// Run: node --test tests/
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { run, deriveEndpoints, buildFilters, applyFilters } from "../cx_auditor.mjs";

const TENANT = "acme";
const NOW = 1_790_000_000_000;
const USERS = [
  { id: "u-alice", username: "alice", email: "alice@corp.com", enabled: true },
  { id: "u-bob", username: "bob", email: "bob@corp.com", enabled: true },
  { id: "u-carol", username: "carol", email: "carol@corp.com", enabled: true },
];
const mk = (i, user, type, ip) => ({
  eventID: `e${i}`, eventDate: `2026-11-0${1 + (i % 9)}T10:00:00Z`, eventType: type,
  auditResource: type.split(".")[0], actionType: type.split(".")[1], actionUserId: user,
  ipAddress: ip, tenantID: "t", data: { note: `n${i}` },
});
// 1200 events -> forces 2 pages; a few distinctive ones for search tests.
const AUDIT = [
  ...Array.from({ length: 1197 }, (_, i) => mk(i, "u-alice", "projects.create", "10.0.0.1")),
  mk(2001, "u-bob", "projects.delete", "10.0.0.2"),
  mk(2002, "u-bob", "users.delete", "192.168.1.5"),
  { ...mk(2003, "u-carol", "scans.trigger", "10.0.0.3"), data: { project: "secret-payments" } },
];
const USER_EVENTS = [
  { time: NOW, type: "REFRESH_TOKEN", clientId: "ast-app", userId: "u-alice", sessionId: "sess-a", ipAddress: "5.6.7.8", details: { refresh_token_type: "Offline" } },
  { time: NOW, type: "REFRESH_TOKEN", clientId: "ast-app", userId: "u-bob", sessionId: "sess-b", ipAddress: "8.8.8.8", details: { refresh_token_type: "Offline" } },
  { time: NOW, type: "LOGIN_ERROR", clientId: "ast-app", userId: "u-carol", sessionId: "", ipAddress: "6.6.6.6", error: "invalid_user_credentials", details: {} },
];
const SESSIONS = {
  "u-alice": [{ id: "sess-a", ipAddress: "1.2.3.4", start: NOW - 864e5, lastAccess: NOW }],
  "u-bob": [{ id: "sess-b", ipAddress: "8.8.8.8", start: NOW - 2 * 864e5, lastAccess: NOW }],
  "u-carol": [],
};

let server, base;
const calls = [];

before(async () => {
  server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    const q = Object.fromEntries(u.searchParams);
    const json = (o, code = 200) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(o)); };
    if (req.method === "POST") return json({ access_token: "AT", expires_in: 1800 });
    calls.push({ path: u.pathname, q, accept: req.headers.accept });
    if (req.headers.authorization !== "Bearer AT") return json({}, 401);
    const admin = `/auth/admin/realms/${TENANT}`;
    if (u.pathname === "/api/audit-events") {
      const off = +q.offset, lim = +q.limit;
      return json({ events: AUDIT.slice(off, off + lim), totalFilteredCount: AUDIT.length });
    }
    if (u.pathname === `${admin}/users`) return json(USERS.slice(+q.first, +q.first + +q.max));
    if (u.pathname === `${admin}/clients`) return json([{ id: "cl", clientId: "ast-app" }]);
    const m = u.pathname.match(/\/users\/([^/]+)\/(offline-sessions\/cl|consents)$/);
    if (m) return json(m[2] === "consents" ? [] : SESSIONS[m[1]] || []);
    if (u.pathname === `${admin}/admin-events`) {
      return json([{ time: NOW, operationType: "DELETE", resourceType: "USER", resourcePath: "users/u-x", authDetails: { userId: "u-bob", ipAddress: "10.0.0.2" } }]);
    }
    if (u.pathname === `${admin}/events`) return json(USER_EVENTS);
    return json({ message: "nf" }, 404);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

/** RFC 4180 CSV parser (quoted fields may contain commas, quotes and newlines). */
function parseCsv(text) {
  const rows = []; let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
    else if (c === '"') q = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; row.push(field); rows.push(row); row = []; field = ""; }
    else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

async function runWith(extra) {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "cxa-"));
  calls.length = 0;
  const origErr = console.error, origLog = console.log;
  console.error = () => {}; console.log = () => {};
  try {
    const code = await run(["--api-key", "K", "--iam-url", base, "--base-url", base, "--tenant", TENANT, "--out", out, ...extra]);
    assert.equal(code, 0);
  } finally { console.error = origErr; console.log = origLog; }
  const csv = (n) => {
    const p = path.join(out, n);
    if (!fs.existsSync(p)) return null;
    const [head, ...rows] = parseCsv(fs.readFileSync(p, "utf8"));
    return rows.map((r) => Object.fromEntries(r.map((v, i) => [head[i], v])));
  };
  return { csv, summary: JSON.parse(fs.readFileSync(path.join(out, "summary.json"), "utf8")) };
}

test("derives tenant and URLs from the key", () => {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const key = `${enc({ alg: "x" })}.${enc({ iss: "https://eu.iam.checkmarx.net/auth/realms/acme" })}.s`;
  assert.deepEqual(deriveEndpoints(key), { iamUrl: "https://eu.iam.checkmarx.net", tenant: "acme", astUrl: "https://eu.ast.checkmarx.net" });
});

test("no filters: everything exported, audit paged with v1.0 Accept", async () => {
  const { csv, summary } = await runWith([]);
  assert.equal(csv("audit_trail.csv").length, 1200);
  const pages = calls.filter((c) => c.path === "/api/audit-events");
  assert.deepEqual(pages.map((c) => c.q.offset), ["0", "1000"]);
  assert.equal(pages[0].accept, "application/json; version=1.0");
  assert.equal(csv("api_keys.csv").length, 2);
  const usage = csv("api_key_usage.csv");
  assert.deepEqual(usage.map((u) => [u.used_by_user, u.api_key_created_by, u.ip_address]),
    [["alice", "alice", "5.6.7.8"], ["bob", "bob", "8.8.8.8"]]);
  assert.equal(summary.per_user.alice.audit_actions, 1197);
});

test("--user by email resolves to the user id and limits key lookups", async () => {
  const { csv, summary } = await runWith(["--user", "bob@corp.com"]);
  assert.deepEqual(csv("audit_trail.csv").map((r) => r.event_id), ["e2001", "e2002"]);
  assert.deepEqual(csv("api_keys.csv").map((r) => r.created_by_user), ["bob"]);
  assert.deepEqual(csv("api_key_usage.csv").map((r) => r.used_by_user), ["bob"]);
  assert.deepEqual(csv("iam_admin_events.csv").map((r) => r.actor_user), ["bob"]);
  // only bob's offline sessions were requested
  assert.deepEqual(calls.filter((c) => c.path.includes("offline-sessions")).map((c) => c.path.split("/")[6]), ["u-bob"]);
  assert.deepEqual(summary.files["audit_trail.csv"].filters_applied, ["user"]);
});

test("multiple values OR, multiple flags AND, wildcards", async () => {
  // (bob OR carol) AND event type matching *.delete OR scans.*  AND ip 10.0.*
  const { csv } = await runWith(["--user", "bob,carol", "--event-type", "*.delete", "--event-type", "scans.*", "--ip", "10.0.*"]);
  assert.deepEqual(csv("audit_trail.csv").map((r) => r.event_id), ["e2001", "e2003"]);
});

test("--text searches inside event data", async () => {
  const { csv } = await runWith(["--text", "SECRET-payments", "--only", "audit"]);
  assert.deepEqual(csv("audit_trail.csv").map((r) => r.event_id), ["e2003"]);
});

test("--only limits API calls and outputs", async () => {
  const { csv } = await runWith(["--only", "keys"]);
  assert.equal(csv("audit_trail.csv"), null);
  assert.equal(calls.some((c) => c.path === "/api/audit-events"), false);
  assert.equal(csv("api_keys.csv").length, 2);
});

test("--errors-only on IAM events; filters skip files without the field", async () => {
  const { csv, summary } = await runWith(["--errors-only", "--only", "events,keys"]);
  assert.deepEqual(csv("iam_user_events.csv").map((r) => r.type), ["LOGIN_ERROR"]);
  assert.equal(csv("api_keys.csv").length, 2);            // keys have no error column: untouched
  assert.deepEqual(summary.files["api_keys.csv"].filters_applied, []);
});

test("--key-id finds who used a specific key", async () => {
  const { csv } = await runWith(["--key-id", "sess-b", "--only", "keys,usage"]);
  assert.deepEqual(csv("api_key_usage.csv").map((r) => r.used_by_user), ["bob"]);
  assert.deepEqual(csv("api_keys.csv").map((r) => r.created_by_user), ["bob"]);
});

test("filter helpers: user expansion does not treat ids as wildcards", () => {
  const f = buildFilters({ user: ["ALICE"] }, [{ id: "u-a*", username: "alice", email: "a@x" }]);
  const { rows } = applyFilters([{ actor_user_id: "u-a*" }, { actor_user_id: "u-abc" }], f);
  assert.deepEqual(rows, [{ actor_user_id: "u-a*" }]);
});
