#!/usr/bin/env node
/**
 * cx_auditor.mjs - export Checkmarx One audit logs and API key usage with one API key.
 *
 * Node.js 18+ only, no npm install needed:
 *
 *   export CX_APIKEY='eyJhbGciOi...'          (PowerShell: $env:CX_APIKEY='eyJ...')
 *   node cx_auditor.mjs --days 90 --out ./audit-out
 *
 * Outputs (CSV + JSON) in --out:
 *   audit_trail.csv        user actions          GET {base}/api/audit-events  (+ legacy /api/audit)
 *   api_keys.csv           key -> creating user  IAM users/{id}/offline-sessions/{ast-app} + consents
 *   api_key_usage.csv      key -> using user/IP  IAM /events (REFRESH_TOKEN on ast-app)
 *   iam_admin_events.csv   IAM admin changes     IAM /admin-events
 *   iam_user_events.csv    logins, token use     IAM /events
 *   summary.json, raw.json
 *
 * Tenant, IAM URL and API URL are read from the key's `iss` claim; override with
 * --tenant / --iam-url / --base-url. Sections the key's owner may not read are
 * skipped (marked in summary.json); the rest still run.
 */
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";

const API_KEY_CLIENT_ID = "ast-app";
const PAGE_SIZE = 100;
const AUDIT_PAGE = 1000;
const TOKEN_USE_EVENTS = new Set(["REFRESH_TOKEN", "CODE_TO_TOKEN", "CLIENT_LOGIN", "TOKEN_EXCHANGE"]);
const V1 = "application/json; version=1.0";

const log = (m) => console.error(m);

// ---------------------------------------------------------------- helpers --
export function decodeJwtClaims(token) {
  try {
    return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
  } catch {
    throw new Error("API key is not a JWT; pass --iam-url, --base-url and --tenant explicitly");
  }
}

export function deriveEndpoints(apiKey) {
  const iss = decodeJwtClaims(apiKey).iss || "";
  const u = new URL(iss);
  const parts = u.pathname.replace(/\/$/, "").split("/");
  const i = parts.indexOf("realms");
  if (i < 0 || !parts[i + 1]) throw new Error(`cannot derive tenant from iss=${iss}`);
  const astHost = u.host.includes("iam.") ? u.host.replace("iam.", "ast.") : u.host;
  return { iamUrl: `${u.protocol}//${u.host}`, tenant: parts[i + 1], astUrl: `${u.protocol}//${astHost}` };
}

const msToIso = (v) => (v === undefined || v === null || v === "" ? "" : new Date(Number(v)).toISOString());
const dateOnly = (d) => d.toISOString().slice(0, 10);

function inWindow(value, start, end) {
  if (!value) return true;
  const t = typeof value === "number" ? new Date(value) : new Date(value);
  return Number.isNaN(t.getTime()) || (t >= start && t <= end);
}

class HttpError extends Error {
  constructor(status, url, body) {
    super(`HTTP ${status} for ${url}: ${String(body).slice(0, 300)}`);
    this.status = status;
  }
}

// ----------------------------------------------------------------- client --
class CxClient {
  constructor({ apiKey, iamUrl, tenant, astUrl }) {
    Object.assign(this, { apiKey, tenant, iamUrl: iamUrl.replace(/\/$/, ""), astUrl: astUrl.replace(/\/$/, "") });
    this.token = null;
  }

  async authenticate() {
    const url = `${this.iamUrl}/auth/realms/${this.tenant}/protocol/openid-connect/token`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: new URLSearchParams({ grant_type: "refresh_token", client_id: API_KEY_CLIENT_ID, refresh_token: this.apiKey }),
    });
    const body = await res.text();
    if (!res.ok) throw new HttpError(res.status, url, body);
    this.token = JSON.parse(body).access_token;
  }

  async get(url, params, accept = "application/json", retried = false) {
    const full = params ? `${url}?${new URLSearchParams(Object.entries(params).filter(([, v]) => v != null))}` : url;
    const res = await fetch(full, { headers: { Authorization: `Bearer ${this.token}`, Accept: accept } });
    const body = await res.text();
    if (res.status === 401 && !retried) {          // access token (30 min) expired mid-run
      await this.authenticate();
      return this.get(full, null, accept, true);
    }
    if (!res.ok) throw new HttpError(res.status, full, body);
    if (!body) return null;
    try { return JSON.parse(body); } catch { return body; }
  }

  admin(p) { return `${this.iamUrl}/auth/admin/realms/${this.tenant}${p}`; }

  async pagedAdmin(p, params = {}) {
    const out = [];
    for (let first = 0; ; first += PAGE_SIZE) {
      const page = (await this.get(this.admin(p), { ...params, first, max: PAGE_SIZE })) || [];
      out.push(...page);
      if (page.length < PAGE_SIZE) return out;
    }
  }

  /** Current audit API: GET /api/audit-events (offset/limit/startDate/endDate). */
  async auditEvents(start, end) {
    const events = [];
    for (let offset = 0; ;) {
      const page = (await this.get(`${this.astUrl}/api/audit-events`,
        { startDate: start.toISOString(), endDate: end.toISOString(), offset, limit: AUDIT_PAGE }, V1)) || {};
      const batch = page.events || [];
      events.push(...batch);
      offset += batch.length;
      const total = page.totalFilteredCount;
      if (!batch.length || batch.length < AUDIT_PAGE || (total != null && offset >= total)) return events;
    }
  }

  /** Deprecated GET /api/audit: today's events inline + pre-signed daily files in `links`. */
  async auditLegacy(start, end) {
    const data = await this.get(`${this.astUrl}/api/audit`, { from: dateOnly(start), to: dateOnly(end) }, V1);
    const events = Array.isArray(data) ? [...data] : [...(data?.events || [])];
    for (const link of data?.links || []) {
      let url = typeof link === "string" ? link : link?.url;
      if (!url) continue;
      if (url.startsWith("/")) url = this.astUrl + url;
      const presigned = /X-Amz-Signature|sig=/.test(url);  // pre-signed URLs reject Authorization
      try {
        const res = await fetch(url, { headers: presigned ? {} : { Authorization: `Bearer ${this.token}` } });
        const text = await res.text();
        if (!res.ok) throw new HttpError(res.status, url, text);
        let body;
        try { body = JSON.parse(text); } catch { body = text.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l)); }
        events.push(...(Array.isArray(body) ? body : body.events || []));
      } catch (e) {
        log(`  ! could not fetch audit file ${url}: ${e.message}`);
      }
    }
    return events.filter((e) => inWindow(e.eventDate, start, end));
  }

  adminEvents(start, end) { return this.pagedAdmin("/admin-events", { dateFrom: dateOnly(start), dateTo: dateOnly(end) }); }
  userEvents(start, end) { return this.pagedAdmin("/events", { dateFrom: dateOnly(start), dateTo: dateOnly(end) }); }
  users() { return this.pagedAdmin("/users", { briefRepresentation: "true" }); }
  async clientUuid(clientId) { return ((await this.get(this.admin("/clients"), { clientId })) || [])[0]?.id || null; }
  async consents(uid) { return (await this.get(this.admin(`/users/${uid}/consents`))) || []; }
  async offlineSessions(uid, cid) { return (await this.get(this.admin(`/users/${uid}/offline-sessions/${cid}`))) || []; }
}

// ---------------------------------------------------------------- reports --
async function buildApiKeyInventory(client, users, onProgress = () => {}) {
  const cid = await client.clientUuid(API_KEY_CLIENT_ID);
  const rows = [];
  let done = 0;
  for (const u of users) {
    onProgress(++done, users.length);
    const sessions = cid ? await client.offlineSessions(u.id, cid) : [];
    const consent = (await client.consents(u.id)).find((c) => c.clientId === API_KEY_CLIENT_ID);
    const grantCreated = consent ? msToIso(consent.createdDate) : "";
    const grantUpdated = consent ? msToIso(consent.lastUpdatedDate) : "";
    const base = { created_by_user: u.username || "", created_by_user_id: u.id, email: u.email || "", user_enabled: u.enabled ?? "" };
    for (const s of sessions) {
      rows.push({ api_key_session_id: s.id || "", ...base, created_at: msToIso(s.start), last_used_at: msToIso(s.lastAccess),
        last_used_from_ip: s.ipAddress || "", offline_grant_first_created: grantCreated, offline_grant_last_updated: grantUpdated });
    }
    if (!sessions.length && consent?.additionalGrants?.some((g) => g.key === "Offline Token")) {
      rows.push({ api_key_session_id: "", ...base, created_at: grantCreated, last_used_at: grantUpdated,
        last_used_from_ip: "", offline_grant_first_created: grantCreated, offline_grant_last_updated: grantUpdated });
    }
  }
  return rows;
}

function buildApiKeyUsage(userEvents, keys, usersById) {
  const owner = Object.fromEntries(keys.filter((k) => k.api_key_session_id).map((k) => [k.api_key_session_id, k.created_by_user]));
  return userEvents
    .filter((e) => e.clientId === API_KEY_CLIENT_ID && TOKEN_USE_EVENTS.has(e.type))
    .map((e) => ({
      time: msToIso(e.time), event_type: e.type,
      used_by_user: usersById[e.userId] || e.details?.username || "", used_by_user_id: e.userId || "",
      ip_address: e.ipAddress || "", api_key_session_id: e.sessionId || "",
      api_key_created_by: owner[e.sessionId] || "",
      is_api_key: e.sessionId in owner || e.details?.refresh_token_type === "Offline",
      error: e.error || "",
    }));
}

const flattenAudit = (e, usersById) => ({
  time: e.eventDate || "", event_id: e.eventID || "", event_type: e.eventType || "",
  audit_resource: e.auditResource || "", action: e.actionType || "",
  actor_user: usersById[e.actionUserId] || e.data?.username || "", actor_user_id: e.actionUserId || "",
  ip_address: e.ipAddress || "", source: e._source || "", data: JSON.stringify(e.data || {}),
});

const flattenAdmin = (e, usersById) => {
  const a = e.authDetails || {};
  return { time: msToIso(e.time), operation: e.operationType || "", resource_type: e.resourceType || "",
    resource_path: e.resourcePath || "", actor_user: usersById[a.userId] || "", actor_user_id: a.userId || "",
    actor_client: a.clientId || "", actor_ip: a.ipAddress || "", error: e.error || "", representation: e.representation || "" };
};

const flattenUser = (e, usersById) => ({
  time: msToIso(e.time), type: e.type || "", user: usersById[e.userId] || e.details?.username || "",
  user_id: e.userId || "", client: e.clientId || "", ip_address: e.ipAddress || "",
  session_id: e.sessionId || "", error: e.error || "", details: JSON.stringify(e.details || {}),
});

// ---------------------------------------------------------------- search --
/**
 * Which row columns each filter looks at. A filter only applies to an output
 * that has at least one of its columns; other outputs are left unfiltered by
 * it (e.g. --event-type does not drop rows from api_keys.csv), and summary.json
 * records which filters were applied to which file.
 */
const FILTER_FIELDS = {
  user: ["actor_user", "actor_user_id", "user", "user_id", "used_by_user", "used_by_user_id",
    "created_by_user", "created_by_user_id", "email", "api_key_created_by"],
  ip: ["ip_address", "actor_ip", "last_used_from_ip"],
  "event-type": ["event_type", "type"],
  action: ["action", "operation"],
  resource: ["audit_resource", "resource_type", "resource_path"],
  "key-id": ["api_key_session_id", "session_id"],
};

const splitValues = (list) => (list || []).flatMap((v) => v.split(",")).map((v) => v.trim()).filter(Boolean);

/** Case-insensitive glob: `*` = any run of chars, `?` = one char. No wildcard = exact match. */
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function globToRegex(pattern) {
  return new RegExp(`^${escapeRe(pattern).replace(/\\\*/g, ".*").replace(/\\\?/g, ".")}$`, "i");
}
const literalRegex = (value) => new RegExp(`^${escapeRe(value)}$`, "i");

export function buildFilters(opts, users = []) {
  const f = {};
  for (const name of Object.keys(FILTER_FIELDS)) {
    const vals = splitValues(opts[name]);
    if (vals.length) f[name] = vals.map(globToRegex);
  }
  // A --user value may be a username, email or id: expand it to all three so
  // e.g. --user alice@corp.com also matches rows that only carry the user id.
  if (f.user) {
    const extra = [];
    for (const u of users) {
      if ([u.username, u.email, u.id].some((v) => v && f.user.some((re) => re.test(v)))) {
        for (const v of [u.username, u.email, u.id]) if (v) extra.push(literalRegex(v));
      }
    }
    f.user.push(...extra);
  }
  const text = splitValues(opts.text).map((t) => t.toLowerCase());
  if (text.length) f.text = text;
  if (opts["errors-only"]) f.errorsOnly = true;
  return f;
}

/** Returns {rows, applied}: rows matching every applicable filter. */
export function applyFilters(rows, filters) {
  const columns = new Set(rows.flatMap((r) => Object.keys(r)));
  const active = Object.entries(FILTER_FIELDS)
    .filter(([name, cols]) => filters[name] && cols.some((c) => columns.has(c)))
    .map(([name, cols]) => [name, cols.filter((c) => columns.has(c))]);
  const applied = active.map(([n]) => n);
  if (filters.text) applied.push("text");
  const useErrors = filters.errorsOnly && columns.has("error");
  if (useErrors) applied.push("errors-only");

  const out = rows.filter((r) => {
    for (const [name, cols] of active) {
      if (!cols.some((c) => r[c] !== undefined && r[c] !== "" && filters[name].some((re) => re.test(String(r[c]))))) return false;
    }
    if (filters.text) {
      const hay = JSON.stringify(r).toLowerCase();
      if (!filters.text.some((t) => hay.includes(t))) return false;
    }
    if (useErrors && !r.error) return false;
    return true;
  });
  return { rows: out, applied };
}

function writeCsv(file, rows) {
  const fields = [];
  for (const r of rows) for (const k of Object.keys(r)) if (!fields.includes(k)) fields.push(k);
  const esc = (v) => {
    const s = v === undefined || v === null ? "" : String(v);
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [(fields.length ? fields : ["empty"]).join(","), ...rows.map((r) => fields.map((f) => esc(r[f])).join(","))];
  fs.writeFileSync(file, lines.join("\r\n") + "\r\n", "utf8");
}

/**
 * Fetch everything for a window. Shared by the CLI and the GUI.
 * opts: {apiKey, iamUrl?, tenant?, astUrl?, start: Date, end: Date,
 *        sections: Set<"audit"|"admin"|"events"|"keys"|"usage">, legacyAudit?, keyUserScope?(user)=>bool}
 * progress(msg) is called with human-readable status lines.
 * Returns {report, users, raw, datasets} where datasets holds flattened rows keyed by
 * audit_trail, iam_admin_events, iam_user_events, api_keys, api_key_usage (only requested ones).
 */
export async function collect(opts, progress = () => {}) {
  const { apiKey, start, end, legacyAudit = false, keyUserScope } = opts;
  const sections = new Set(opts.sections || SECTIONS);
  let { iamUrl, tenant, astUrl } = opts;
  if (!(iamUrl && tenant && astUrl)) {
    const d = deriveEndpoints(apiKey);
    iamUrl ||= d.iamUrl; tenant ||= d.tenant; astUrl ||= d.astUrl;
  }
  progress(`tenant=${tenant}  iam=${iamUrl}  api=${astUrl}`);
  progress(`window ${start.toISOString()} -> ${end.toISOString()}`);

  const client = new CxClient({ apiKey, iamUrl, tenant, astUrl });
  await client.authenticate();
  progress("authenticated");

  const report = { tenant, iamUrl, astUrl, from: start.toISOString(), to: end.toISOString(),
    fetchedAt: new Date().toISOString(), sections: {} };
  const section = async (name, fn) => {
    progress(`- ${name} ...`);
    try {
      const r = await fn();
      report.sections[name] = { status: "ok", fetched: r.length };
      progress(`  ${name}: ${r.length} records`);
      return r;
    } catch (e) {
      if (!(e instanceof HttpError)) throw e;
      const hint = [401, 403].includes(e.status) ? " (API key owner lacks permission)" : "";
      report.sections[name] = { status: `failed: HTTP ${e.status}${hint}` };
      progress(`  ! ${name} skipped: ${e.message}${hint}`);
      return [];
    }
  };

  const users = await section("users", () => client.users());
  const usersById = Object.fromEntries(users.map((u) => [u.id, u.username || ""]));

  let audit = [], adminEv = [], userEv = [], keys = [];
  if (sections.has("audit")) {
    audit = await section("audit_trail", async () => {
      let events = [];
      let legacy = legacyAudit;
      try {
        events = (await client.auditEvents(start, end)).map((e) => ({ ...e, _source: "audit-events" }));
      } catch (e) {
        if (!(e instanceof HttpError) || e.status !== 404) throw e;
        progress("  /api/audit-events not available on this tenant; using legacy /api/audit");
        legacy = true;
      }
      if (legacy) {
        const seen = new Set(events.map((e) => e.eventID).filter(Boolean));
        for (const e of await client.auditLegacy(start, end))
          if (!e.eventID || !seen.has(e.eventID)) events.push({ ...e, _source: "audit-legacy" });
      }
      return events.sort((x, y) => String(x.eventDate || "").localeCompare(String(y.eventDate || "")));
    });
  }
  if (sections.has("admin")) adminEv = await section("iam_admin_events", () => client.adminEvents(start, end));
  if (sections.has("events") || sections.has("usage")) userEv = await section("iam_user_events", () => client.userEvents(start, end));
  if ((sections.has("keys") || sections.has("usage")) && users.length) {
    const scope = keyUserScope ? users.filter(keyUserScope) : users;
    if (keyUserScope && !scope.length) progress("  note: no IAM user matches the user filter; API key inventory will be empty");
    keys = await section("api_keys", () => buildApiKeyInventory(client, scope, (i, n) => {
      if (i % 25 === 0 || i === n) progress(`  api_keys: ${i}/${n} users checked`);
    }));
  }

  const datasets = {};
  if (sections.has("audit")) datasets.audit_trail = audit.map((e) => flattenAudit(e, usersById));
  if (sections.has("admin")) datasets.iam_admin_events = adminEv.map((e) => flattenAdmin(e, usersById));
  if (sections.has("events")) datasets.iam_user_events = userEv.map((e) => flattenUser(e, usersById));
  if (sections.has("keys")) datasets.api_keys = keys;
  if (sections.has("usage")) datasets.api_key_usage = buildApiKeyUsage(userEv, keys, usersById);

  const userList = users.map((u) => ({ id: u.id, username: u.username || "", email: u.email || "", enabled: u.enabled }));
  return { report, users: userList, raw: { audit_trail: audit, iam_admin_events: adminEv, iam_user_events: userEv, api_keys: keys }, datasets };
}

// ------------------------------------------------------------------- main --
export const SECTIONS = ["audit", "admin", "events", "keys", "usage"];

const HELP = `usage: node cx_auditor.mjs [options]

Connection (tenant/URLs are normally derived from the key):
  --api-key KEY        Checkmarx One API key (default: $CX_APIKEY)
  --base-url URL       e.g. https://eu.ast.checkmarx.net
  --iam-url URL        e.g. https://eu.iam.checkmarx.net
  --tenant NAME

Time window:
  --days N             look back N days (default 30)
  --from DATE          start, e.g. 2026-10-01 or 2026-10-01T08:00:00Z (overrides --days)
  --to DATE            end (default: now)

What to fetch:
  --only LIST          comma list of: ${SECTIONS.join(",")}   (default: all)
                       usage needs events (+ keys to name the key owner)
  --legacy-audit       also pull deprecated /api/audit (events before 2026-03-29)

Search (repeat a flag or comma-separate values; OR within a flag, AND across flags;
* and ? wildcards, case-insensitive):
  --user V             username, email or user id (matches actor, key creator, key user)
  --ip V               IP address, e.g. 10.20.*
  --event-type V       audit eventType or IAM event type, e.g. projects.* or REFRESH_TOKEN
  --action V           audit actionType or IAM admin operation, e.g. delete, CREATE
  --resource V         audit resource / IAM resource type or path, e.g. users*
  --key-id V           API key session id
  --text V             free-text substring anywhere in the row (incl. event data)
  --errors-only        only IAM events that carry an error (e.g. failed logins)

Output:
  --out DIR            output directory (default ./audit-out)
  --print              also print matching rows to the terminal
  -h, --help`;

function parseDate(v, name) {
  const d = new Date(/^\d{4}-\d{2}-\d{2}$/.test(v) ? `${v}T00:00:00Z` : v);
  if (Number.isNaN(d.getTime())) throw new Error(`invalid ${name}: ${v}`);
  return d;
}

export async function run(argv = process.argv.slice(2)) {
  const multi = { type: "string", multiple: true };
  const { values: a } = parseArgs({
    args: argv,
    options: {
      "api-key": { type: "string" }, "base-url": { type: "string" }, "iam-url": { type: "string" },
      tenant: { type: "string" }, days: { type: "string", default: "30" },
      from: { type: "string" }, to: { type: "string" }, only: { type: "string" },
      out: { type: "string", default: "audit-out" }, "legacy-audit": { type: "boolean", default: false },
      user: multi, ip: multi, "event-type": multi, action: multi, resource: multi, "key-id": multi, text: multi,
      "errors-only": { type: "boolean", default: false }, print: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  if (a.help) { console.log(HELP); return 0; }
  const apiKey = a["api-key"] || process.env.CX_APIKEY;
  if (!apiKey) { log("error: provide the API key via --api-key or CX_APIKEY"); return 2; }

  const end = a.to ? parseDate(a.to, "--to") : new Date();
  const start = a.from ? parseDate(a.from, "--from") : new Date(end.getTime() - Number(a.days) * 86_400_000);
  if (start > end) { log("error: --from is after --to"); return 2; }
  if (end - start > 365 * 86_400_000) log("warning: window exceeds 365 days; audit APIs only keep 365 days");

  const only = new Set(a.only ? splitValues([a.only]).map((s) => s.toLowerCase()) : SECTIONS);
  const bad = [...only].filter((s) => !SECTIONS.includes(s));
  if (bad.length) { log(`error: unknown --only value(s): ${bad.join(", ")}`); return 2; }

  let collected;
  try {
    collected = await collect({
      apiKey, iamUrl: a["iam-url"], tenant: a.tenant, astUrl: a["base-url"], start, end, sections: only,
      legacyAudit: a["legacy-audit"],
      // --user also narrows the per-user API key lookups (one IAM call pair per user otherwise)
      keyUserScope: (u) => {
        const f = buildFilters({ user: a.user }, []);
        return !f.user || [u.username, u.email, u.id].some((v) => v && f.user.some((re) => re.test(v)));
      },
    }, log);
  } catch (e) {
    if (e instanceof HttpError) { log(`error: ${e.message}`); return 1; }
    throw e;
  }
  const { report, users, raw, datasets } = collected;
  fs.mkdirSync(a.out, { recursive: true });
  const filters = buildFilters(a, users);
  report.files = {};
  report.filters = Object.fromEntries(
    ["user", "ip", "event-type", "action", "resource", "key-id", "text"].filter((k) => a[k]).map((k) => [k, splitValues(a[k])]));
  if (a["errors-only"]) report.filters["errors-only"] = true;
  const outputs = Object.fromEntries(Object.entries(datasets).map(([k, v]) => [`${k}.csv`, v]));

  for (const [name, all] of Object.entries(outputs)) {
    const { rows, applied } = applyFilters(all, filters);
    outputs[name] = rows;
    report.files[name] = { total: all.length, matched: rows.length, filters_applied: applied };
    writeCsv(path.join(a.out, name), rows);
    log(`  ${name}: ${rows.length}/${all.length} rows${applied.length ? ` (filters: ${applied.join(", ")})` : ""}`);
    if (a.print && rows.length) { console.log(`\n== ${name} (${rows.length})`); console.table(rows.map(trimForTable)); }
  }

  const perUser = {};
  const bump = (who, field) => { if (!who) return; (perUser[who] ||= {})[field] = (perUser[who][field] || 0) + 1; };
  for (const k of outputs["api_keys.csv"] || []) bump(k.created_by_user, "api_keys_created");
  for (const u of outputs["api_key_usage.csv"] || []) {
    const who = u.used_by_user || u.used_by_user_id;
    bump(who, "api_key_uses");
    if (who && u.ip_address) (perUser[who].api_key_ips ||= new Set()).add(u.ip_address);
  }
  for (const r of outputs["audit_trail.csv"] || []) bump(r.actor_user || r.actor_user_id, "audit_actions");
  for (const s of Object.values(perUser)) if (s.api_key_ips) s.api_key_ips = [...s.api_key_ips].sort();
  report.per_user = perUser;

  fs.writeFileSync(path.join(a.out, "raw.json"), JSON.stringify(raw, null, 2));
  fs.writeFileSync(path.join(a.out, "summary.json"), JSON.stringify(report, null, 2));
  log(`done -> ${path.resolve(a.out)}`);
  return 0;
}

/** Keep console.table readable: drop bulky JSON columns, cap cell width. */
function trimForTable(r) {
  const o = {};
  for (const [k, v] of Object.entries(r)) {
    if (["data", "details", "representation"].includes(k)) continue;
    const s = String(v ?? "");
    o[k] = s.length > 40 ? `${s.slice(0, 37)}...` : s;
  }
  return o;
}

/**
 * True when the file at metaUrl is the script node was started with. Compares real
 * paths (case-insensitively on Windows) so drive-letter case, spaces or symlinks
 * cannot make the entry point silently do nothing.
 */
export function isMainModule(metaUrl) {
  if (!process.argv[1]) return false;
  try {
    const norm = (p) => { const r = fs.realpathSync(p); return process.platform === "win32" ? r.toLowerCase() : r; };
    return norm(process.argv[1]) === norm(fileURLToPath(metaUrl));
  } catch {
    return false;
  }
}

// @@CLI_MAIN_START (removed from the standalone bundle)
if (isMainModule(import.meta.url)) {
  run().then((code) => process.exit(code), (e) => { log(`error: ${e.message}`); process.exit(1); });
}
// @@CLI_MAIN_END
