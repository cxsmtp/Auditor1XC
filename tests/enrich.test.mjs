// Run: node --test tests/enrich.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { Directory, buildTokenIndex, attributeCredential, describeTarget, attributeAiRuns, buildActivity } from "../cx_enrich.mjs";
import { collect } from "../cx_auditor.mjs";

const A = "aaaaaaaa-0000-4000-8000-000000000001"; // alice
const B = "bbbbbbbb-0000-4000-8000-000000000002"; // bob
const D = "dddddddd-0000-4000-8000-000000000004"; // deleted user
const S = "55555555-0000-4000-8000-000000000005"; // service account of OAuth client "jenkins"
const T0 = Date.parse("2026-11-01T10:00:00Z");
const min = 60_000;

function dirWithPeople() {
  const d = new Directory();
  d.add({ id: A, username: "alice", email: "alice@corp.com", firstName: "Alice", lastName: "Ng", source: "iam" });
  d.add({ id: B, username: "bob", email: "bob@corp.com", source: "iam" });
  d.add({ id: S, username: "service-account-jenkins", clientId: "jenkins", type: "service-account", source: "service-account" });
  return d;
}

test("directory: labels, precedence, deleted and unknown users", () => {
  const d = dirWithPeople();
  assert.equal(d.label(A), "Alice Ng");
  assert.equal(d.label(B), "bob");
  assert.equal(d.label(S), "OAuth client: jenkins");
  assert.equal(d.label("eeeeeeee-0000-4000-8000-000000000009"), "unknown user eeeeeeee");
  d.add({ id: A, username: "spoofed", email: "x@evil", source: "hint" });       // hints never override IAM
  assert.equal(d.person(A).email, "alice@corp.com");
  d.learnFromAudit([{ actionUserId: D, data: { id: D, username: "dave", email: "dave@corp.com" } }]);
  d.add({ id: D, type: "deleted-user", source: "lookup" });
  assert.equal(d.label(D), "dave (deleted)");
  assert.equal(d.person(D).email, "dave@corp.com");
});

test("credential attribution: API key, browser, OAuth client, ambiguity and gaps", () => {
  const d = dirWithPeople();
  const ev = [
    { userId: A, type: "REFRESH_TOKEN", sessionId: "key-1", ipAddress: "34.1.1.1", time: T0 - 10 * min },
    { userId: B, type: "LOGIN", sessionId: "web-1", ipAddress: "10.0.0.2", time: T0 - 5 * min },
    { userId: B, type: "REFRESH_TOKEN", sessionId: "key-2", ipAddress: "52.0.0.9", time: T0 - 3 * min, details: { refresh_token_type: "Offline" } },
    { userId: A, type: "LOGIN_ERROR", ipAddress: "1.1.1.1", time: T0 - min, error: "invalid_user_credentials" },
  ];
  const idx = buildTokenIndex(ev, new Set(["key-1"]));

  const a = attributeCredential({ userId: A, t: T0, ip: "34.1.1.1" }, idx, d);
  assert.deepEqual([a.via, a.via_key, a.via_confidence], ["API key", "key-1", "high"]);
  assert.match(a.via_evidence, /10 min before/);

  assert.equal(attributeCredential({ userId: A, t: T0, ip: "9.9.9.9" }, idx, d).via_confidence, "medium");
  assert.equal(attributeCredential({ userId: A, t: T0 + 45 * min, ip: "34.1.1.1" }, idx, d).via_confidence, "none"); // token would have expired

  // bob: browser from 10.0.0.2 and API key from 52.0.0.9 in the same window -> IP decides
  const b1 = attributeCredential({ userId: B, t: T0, ip: "10.0.0.2" }, idx, d);
  assert.deepEqual([b1.via, b1.via_confidence], ["Browser sign-in", "high"]);
  const b2 = attributeCredential({ userId: B, t: T0, ip: "52.0.0.9" }, idx, d);
  assert.deepEqual([b2.via, b2.via_key], ["API key", "key-2"]);
  const b3 = attributeCredential({ userId: B, t: T0, ip: "" }, idx, d);
  assert.deepEqual([b3.via, b3.via_confidence], ["API key", "low"]);    // most recent before, flagged ambiguous
  assert.match(b3.via_evidence, /Also active: Browser sign-in/);

  assert.equal(attributeCredential({ userId: S, t: T0, ip: "" }, idx, d).via_confidence, "confirmed");
  assert.equal(attributeCredential({ userId: D, t: T0, ip: "" }, idx, d).via, "unknown");
});

test("targets: project ids named, other people resolved", () => {
  const d = dirWithPeople();
  const r = describeTarget({ projectId: "p-1", userId: B, roleName: "ast-admin" }, d, A, new Map([["p-1", "payments-api"]]));
  assert.equal(r.target, "project payments-api · role ast-admin");
  assert.equal(r.target_people, "bob");
});

test("AI runs are linked to the scan (and credential) that triggered them", () => {
  const audit = [
    { time: "2026-11-01T09:00:00Z", event_type: "scans.create", data: '{"projectName":"payments-api"}', actor_name: "Alice Ng", actor_email: "alice@corp.com", via: "API key", via_key: "key-1", event_id: "e1" },
    { time: "2026-11-01T09:30:00Z", event_type: "scans.create", data: '{"projectName":"web"}', actor_name: "bob", actor_email: "bob@corp.com", via: "Browser sign-in", via_key: "", event_id: "e2" },
  ];
  const [hit, miss] = attributeAiRuns([
    { id: "r1", origin: "auto_triage", status: "completed", completedAt: "2026-11-01T10:00:00Z", projectName: "payments-api", scanners: ["SAST"], counts: { processed: 12, succeeded: 11, failed: 1, skipped: 0 } },
    { id: "r2", origin: "auto_remediation", status: "completed", completedAt: "2026-11-01T10:00:00Z", projectName: "mobile", scanners: ["SCA"] },
  ], audit);
  assert.deepEqual([hit.triggered_by, hit.triggered_via, hit.triggered_via_key, hit.attribution_confidence, hit.findings_processed],
    ["Alice Ng", "API key", "key-1", "likely", 12]);
  assert.equal(miss.attribution_confidence, "none");
});

test("activity timeline merges sources, newest first, people not ids", () => {
  const rows = buildActivity({
    audit: [{ time: "2026-11-01T10:00:00Z", actor_name: "Alice Ng", actor_email: "a@c", event_type: "projects.delete", via: "API key", via_key: "k", via_confidence: "high", event_id: "e" }],
    keys: [{ created_at: "2026-10-01T00:00:00Z", created_by_name: "Alice Ng", email: "a@c", api_key_session_id: "k" }],
    userEvents: [{ time: "2026-11-02T00:00:00Z", user_name: "bob", type: "LOGIN_ERROR", error: "bad", ip_address: "6.6.6.6" },
      { time: "2026-11-02T00:00:00Z", user_name: "bob", type: "REFRESH_TOKEN" }],
  });
  assert.deepEqual(rows.map((r) => [r.person, r.action]), [
    ["bob", "sign-in.login_error (failed)"], ["Alice Ng", "projects.delete"], ["Alice Ng", "api-key.created"]]);
});

test("collect(): end to end against a mock tenant", async () => {
  const TEN = "acme";
  const adm = `/auth/admin/realms/${TEN}`;
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://x"), q = Object.fromEntries(u.searchParams);
    const json = (o, c = 200) => { res.writeHead(c, { "Content-Type": "application/json" }); res.end(JSON.stringify(o)); };
    if (req.method === "POST") return json({ access_token: "AT" });
    const p = u.pathname;
    if (p === "/api/audit-events") return json(+q.offset ? { events: [] } : { totalFilteredCount: 3, events: [
      { eventID: "e1", eventDate: "2026-11-01T10:00:00Z", eventType: "projects.delete", auditResource: "projects", actionType: "delete", actionUserId: A, ipAddress: "34.1.1.1", data: { projectId: "p-1" } },
      { eventID: "e2", eventDate: "2026-11-01T09:00:00Z", eventType: "scans.create", auditResource: "scans", actionType: "create", actionUserId: S, ipAddress: "", data: { projectId: "p-1" } },
      { eventID: "e3", eventDate: "2026-11-01T08:00:00Z", eventType: "users.login", auditResource: "users", actionType: "login", actionUserId: D, ipAddress: "", data: { id: D, username: "dave" } },
    ] });
    if (p === "/api/projects") return json({ projects: [{ id: "p-1", name: "payments-api" }], totalCount: 1 });
    if (p === "/api/ai-agents-coordinator/history") return json({ metaData: {}, history: +q.offset ? [] : [
      { id: "r1", origin: "auto_triage", status: "completed", completedAt: "2026-11-01T09:40:00Z", projectName: "payments-api", scanners: ["SAST"], counts: { processed: 5 } }] });
    if (p === `${adm}/users` && !q.clientId) return json(+q.first ? [] : [
      { id: A, username: "alice", email: "alice@corp.com", firstName: "Alice", lastName: "Ng", enabled: true },
      { id: B, username: "bob", email: "bob@corp.com", enabled: false }]);
    if (p === `${adm}/clients`) return json(q.clientId ? [{ id: "cl-ast", clientId: "ast-app" }] : [
      { id: "cl-ast", clientId: "ast-app" }, { id: "cl-j", clientId: "jenkins", serviceAccountsEnabled: true }]);
    if (p === `${adm}/clients/cl-j/service-account-user`) return json({ id: S, username: "service-account-jenkins" });
    if (p === `${adm}/users/${D}`) return json({ error: "User not found" }, 404);
    if (p === `${adm}/users/${A}/offline-sessions/cl-ast`) return json([{ id: "key-1", start: T0 - 86400000, lastAccess: T0, ipAddress: "34.1.1.1" }]);
    if (/offline-sessions|consents$/.test(p)) return json([]);
    if (p === `${adm}/admin-events`) return json([]);
    if (p === `${adm}/events`) return json(+q.first ? [] : [
      { time: T0 - 10 * min, type: "REFRESH_TOKEN", clientId: "ast-app", userId: A, sessionId: "key-1", ipAddress: "34.1.1.1" }]);
    return json({ m: "nf" }, 404);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const out = await collect({ apiKey: "K", iamUrl: base, astUrl: base, tenant: TEN,
      start: new Date("2026-10-01T00:00:00Z"), end: new Date("2026-11-05T00:00:00Z") });
    const { audit_trail: audit, api_keys: keys, ai_runs: ai, activity, people } = out.datasets;
    const byId = Object.fromEntries(audit.map((r) => [r.event_id, r]));

    assert.deepEqual([byId.e1.actor_name, byId.e1.actor_email, byId.e1.via, byId.e1.via_key, byId.e1.via_confidence, byId.e1.target],
      ["Alice Ng", "alice@corp.com", "API key", "key-1", "high", "project payments-api"]);
    assert.deepEqual([byId.e2.actor_name, byId.e2.via], ["OAuth client: jenkins", "OAuth client"]);
    assert.deepEqual([byId.e3.actor_name, byId.e3.actor_type], ["dave (deleted)", "deleted-user"]);

    assert.deepEqual([keys[0].created_by_name, keys[0].actions_via_key, keys[0].action_types], ["Alice Ng", 1, "projects.delete ×1"]);
    assert.deepEqual([ai[0].triggered_by, ai[0].triggered_via, ai[0].attribution_confidence], ["OAuth client: jenkins", "OAuth client", "likely"]);
    assert.ok(activity.some((r) => r.person === "Alice Ng" && r.action === "api-key.created"));
    assert.ok(people.some((p) => p.name === "OAuth client: jenkins" && p.type === "service-account"));
    assert.equal(out.report.attribution.by_api_key, 1);
    assert.ok(Object.values(out.report.sections).every((s) => s.status === "ok"), JSON.stringify(out.report.sections));
  } finally {
    server.close();
  }
});
