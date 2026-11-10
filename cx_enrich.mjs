/**
 * cx_enrich.mjs - turn raw Checkmarx One / IAM records into "who did what".
 *
 * Pure functions (no network) so every rule here is unit-tested:
 *  - Directory: resolves any user / service-account id to a person (name, email, type).
 *  - attributeCredential: works out HOW an action was authenticated (API key, browser
 *    sign-in, OAuth client) from the IAM token events of that user.
 *  - describeTarget: what an audit event acted on, with user ids resolved to people.
 *  - attributeAiRuns: links AI Triage/Remediation runs (credit consumption) to the scan,
 *    and therefore the person, that most likely triggered them.
 *  - buildActivity: one merged, person-centric timeline from every source.
 *
 * Every inference carries a confidence and the evidence behind it, so the UI can show
 * "how do we know" instead of asking anyone to trust a guess.
 */

/** Checkmarx One access tokens expire after 30 minutes (Authentication API docs). Any API
 * call at time t was therefore made with a token issued in [t - 30 min, t]. */
export const TOKEN_TTL_MS = 30 * 60 * 1000;
const SKEW_MS = 2 * 60 * 1000;            // tolerate clock skew between services
const AI_LOOKBACK_MS = 24 * 3600 * 1000;  // a scan that triggers an AI run precedes it by < 1 day
const API_KEY_CLIENT = "ast-app";
const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const iso = (v) => {
  if (v === undefined || v === null || v === "") return "";
  const d = typeof v === "number" ? new Date(v) : new Date(String(v));
  return Number.isNaN(d.getTime()) ? String(v) : d.toISOString();
};
const ms = (v) => (typeof v === "number" ? v : Date.parse(v));
const short = (id) => (id ? String(id).slice(0, 8) : "");
const SOURCE_RANK = { iam: 3, "service-account": 3, lookup: 2, hint: 1 };

// ------------------------------------------------------------- directory --
export class Directory {
  constructor() { this.byId = new Map(); }

  /** Add or merge a person. Higher-ranked sources (IAM) win; hints only fill gaps. */
  add(p) {
    if (!p?.id) return;
    const cur = this.byId.get(p.id);
    if (!cur) { this.byId.set(p.id, { type: "user", ...p }); return; }
    const stronger = (SOURCE_RANK[p.source] || 0) > (SOURCE_RANK[cur.source] || 0);
    for (const [k, v] of Object.entries(p)) {
      if (v === undefined || v === null || v === "") continue;
      if (stronger || cur[k] === undefined || cur[k] === null || cur[k] === "") cur[k] = v;
    }
  }

  get(id) { return id ? this.byId.get(id) : undefined; }

  /** Human label: "Jane Doe", else username/email; OAuth clients get "OAuth client: x". */
  label(id) {
    const p = this.get(id);
    if (!p) return id ? `unknown user ${short(id)}` : "";
    if (p.type === "service-account") return `OAuth client: ${p.clientId || p.username}`;
    const full = [p.firstName, p.lastName].filter(Boolean).join(" ").trim();
    const name = full || p.username || p.email || `unknown user ${short(id)}`;
    return p.type === "deleted-user" ? `${name} (deleted)` : name;
  }

  person(id) {
    const p = this.get(id);
    return {
      name: this.label(id), email: p?.email || "", username: p?.username || "",
      type: p ? p.type : id ? "unknown" : "", id: id || "",
    };
  }

  /** Learn names from event payloads (e.g. users.login data {id, username}). */
  learnFromAudit(events) {
    for (const e of events) {
      walk(e.data, (o) => {
        const id = o.id || o.userId || o.user_id || o.actionUserId;
        if (typeof id !== "string" || !ID_RE.test(id)) return;
        const username = o.username || o.userName || o.user_name;
        const email = o.email || o.emailAddress;
        if (username || email) this.add({ id, username, email, firstName: o.firstName, lastName: o.lastName, source: "hint" });
      });
      // login-style events whose payload names the actor without an id
      if (e.actionUserId && e.data && typeof e.data.username === "string" && !e.data.id) {
        this.add({ id: e.actionUserId, username: e.data.username, email: e.data.email, source: "hint" });
      }
    }
  }

  learnFromAdminEvents(events) {
    for (const e of events) {
      const m = String(e.resourcePath || "").match(/^users\/([0-9a-f-]{36})/i);
      if (!m || !e.representation) continue;
      try {
        const r = JSON.parse(e.representation);
        if (r && (r.username || r.email)) {
          this.add({ id: m[1], username: r.username, email: r.email, firstName: r.firstName, lastName: r.lastName, source: "hint" });
        }
      } catch { /* representation is not always JSON */ }
    }
  }

  learnFromUserEvents(events) {
    for (const e of events) {
      const u = e.details?.username;
      if (e.userId && u) this.add({ id: e.userId, username: u.includes("@") ? undefined : u, email: u.includes("@") ? u : undefined, source: "hint" });
    }
  }

  /** Ids referenced anywhere that IAM has not confirmed yet (unknown, or only named by an event payload). */
  unresolved(ids) {
    return [...new Set(ids)].filter((id) => id && ID_RE.test(id) && (SOURCE_RANK[this.get(id)?.source] || 0) < SOURCE_RANK.lookup);
  }

  list() { return [...this.byId.values()]; }
}

function walk(obj, fn, depth = 0) {
  if (!obj || typeof obj !== "object" || depth > 4) return;
  if (!Array.isArray(obj)) fn(obj);
  for (const v of Object.values(obj)) if (v && typeof v === "object") walk(v, fn, depth + 1);
}

// --------------------------------------------------------- token index --
/**
 * Per user, the time-sorted list of token issuances from IAM events, each classified:
 *  api-key       REFRESH_TOKEN on an offline session (= Checkmarx One API key)
 *  oauth-client  CLIENT_LOGIN (client-credentials grant)
 *  browser       interactive LOGIN / CODE_TO_TOKEN / refresh of an online session
 */
export function buildTokenIndex(userEvents, keySessionIds = new Set()) {
  const idx = new Map();
  for (const e of userEvents) {
    if (!e.userId || e.error) continue;
    let kind = null;
    if (e.type === "CLIENT_LOGIN") kind = "oauth-client";
    else if (e.type === "REFRESH_TOKEN" && (keySessionIds.has(e.sessionId) || e.details?.refresh_token_type === "Offline")) kind = "api-key";
    else if (["LOGIN", "CODE_TO_TOKEN", "REFRESH_TOKEN", "TOKEN_EXCHANGE"].includes(e.type)) kind = "browser";
    if (!kind) continue;
    const list = idx.get(e.userId) || [];
    list.push({ t: ms(e.time), kind, sessionId: e.sessionId || "", ip: e.ipAddress || "", type: e.type, clientId: e.clientId || "" });
    idx.set(e.userId, list);
  }
  for (const list of idx.values()) list.sort((a, b) => a.t - b.t);
  return idx;
}

const VIA_LABEL = { "api-key": "API key", browser: "Browser sign-in", "oauth-client": "OAuth client" };

/**
 * How was the action by `userId` at time `t` from `ip` authenticated?
 * Returns {via, via_key, via_confidence, via_evidence}.
 *  confirmed  actor is an OAuth client's service account (only one way to act)
 *  high       exactly one credential issued tokens to this user in the window, from the same IP
 *  medium     exactly one credential in the window, but not from the same IP
 *  low        several credentials were active; the most recent one before the action is shown
 *  none       no token events in the window (IAM event saving off, or outside retention)
 */
export function attributeCredential({ userId, t, ip }, tokenIndex, dir) {
  const p = dir?.get(userId);
  if (p?.type === "service-account") {
    return { via: "OAuth client", via_key: p.clientId || "", via_confidence: "confirmed", via_evidence: "the actor is the service account of this OAuth client" };
  }
  const when = ms(t);
  const list = tokenIndex.get(userId) || [];
  if (Number.isNaN(when) || !list.length) {
    return { via: "unknown", via_key: "", via_confidence: "none",
      via_evidence: list.length ? "event has no usable time" : "no IAM sign-in/token events for this user in the fetched data (IAM event saving off or outside retention)" };
  }
  const inWin = list.filter((e) => e.t >= when - TOKEN_TTL_MS - SKEW_MS && e.t <= when + SKEW_MS);
  if (!inWin.length) {
    return { via: "unknown", via_key: "", via_confidence: "none", via_evidence: "no token was issued to this user in the 30 minutes before this action" };
  }
  const sameIp = ip ? inWin.filter((e) => e.ip === ip) : [];
  const pool = sameIp.length ? sameIp : inWin;
  const sources = new Map();
  for (const e of pool) sources.set(e.kind === "api-key" ? `api-key:${e.sessionId}` : e.kind, e);
  const before = pool.filter((e) => e.t <= when + SKEW_MS);
  const pick = (before.length ? before : pool).at(-1);
  const mins = Math.round((when - pick.t) / 60000);
  const ago = mins >= 0 ? `${mins} min before` : `${-mins} min after`;
  const where = pick.ip ? ` from ${pick.ip}` : "";
  const keyTxt = pick.kind === "api-key" ? ` (key session ${short(pick.sessionId)})` : "";
  let confidence, evidence;
  if (sources.size === 1) {
    confidence = sameIp.length ? "high" : "medium";
    evidence = `${pick.type}${keyTxt}${where}, ${ago}; only credential this user used in the 30-min window${sameIp.length ? ", same IP as the action" : ", but from a different IP than the action"}`;
  } else {
    confidence = "low";
    const others = [...sources.keys()].filter((k) => k !== (pick.kind === "api-key" ? `api-key:${pick.sessionId}` : pick.kind));
    evidence = `${sources.size} credentials active in the window; most recent before the action: ${pick.type}${keyTxt}${where}, ${ago}. Also active: ${others.map((k) => (k.startsWith("api-key:") ? `API key ${short(k.slice(8))}` : VIA_LABEL[k])).join(", ")}`;
  }
  return { via: VIA_LABEL[pick.kind], via_key: pick.kind === "api-key" ? pick.sessionId : "", via_confidence: confidence, via_evidence: evidence };
}

// --------------------------------------------------------------- targets --
const TARGET_KEYS = ["projectName", "project_name", "applicationName", "application", "name", "reportName", "repoUrl",
  "repository", "branch", "environmentName", "clientId", "groupName", "roleName", "role", "scanId", "projectId", "id"];

/** Short description of what an audit event acted on + any other people it names. */
export function describeTarget(data, dir, actorId, projectNames = new Map()) {
  if (!data || typeof data !== "object") return { target: "", target_people: "" };
  const parts = [];
  const pid = data.projectId ?? data.project?.id;
  if (pid !== undefined && projectNames.has(String(pid))) parts.push(`project ${projectNames.get(String(pid))}`);
  for (const k of TARGET_KEYS) {
    if (k === "projectId" && parts.length && pid !== undefined && projectNames.has(String(pid))) continue;
    const v = data[k] ?? data.project?.[k] ?? data.resource?.[k];
    if (v === undefined || v === null || typeof v === "object" || v === "") continue;
    if (k === "id" && v === actorId) continue;
    const s = String(v);
    if (!(ID_RE.test(s) && dir?.get(s))) parts.push(k === "id" || k === "name" ? s : `${k.replace(/Name$/, "")} ${s}`);
    if (parts.length >= 2) break;
  }
  const people = new Set();
  walk(data, (o) => {
    for (const [k, v] of Object.entries(o)) {
      if (typeof v !== "string") continue;
      if (ID_RE.test(v) && v !== actorId && dir?.get(v) && /user|member|owner|assignee|^id$|entity/i.test(k)) people.add(dir.label(v));
    }
  });
  return { target: parts.join(" · "), target_people: [...people].join(", ") };
}

// --------------------------------------------------------- AI credit use --
/**
 * Automated AI Triage/Remediation runs consume Checkmarx Assist / AI credits. The history
 * API records the project but not who triggered the run, so we look for the scan of that
 * project that finished most recently before the run (within 24 h) and attribute the run
 * to the person - and credential - that started that scan. Always labelled "likely".
 */
export function attributeAiRuns(runs, auditRows, projectNames = new Map()) {
  const scans = auditRows
    .filter((r) => /^(scans\.(create|trigger)|dast-scans\.(create|trigger)|scan-schedulers\.)/.test(r.event_type))
    .map((r) => ({ r, t: ms(r.time), hay: `${r.data || ""} ${r.target || ""}`.toLowerCase() }));
  return runs.map((run) => {
    const done = ms(run.completedAt || run.startedAt || run.createdAt);
    const project = run.projectName || "";
    const ids = [...projectNames].filter(([, n]) => n === project).map(([id]) => id.toLowerCase());
    let match = null;
    if (project && !Number.isNaN(done)) {
      const needles = [project.toLowerCase(), ...ids];
      for (const s of scans) {
        if (s.t > done + SKEW_MS || s.t < done - AI_LOOKBACK_MS) continue;
        if (!needles.some((n) => n && s.hay.includes(n))) continue;
        if (!match || s.t > match.t) match = s;
      }
    }
    const c = run.counts || {};
    const base = {
      time: iso(run.completedAt) || iso(run.startedAt) || "",
      origin: run.origin || "", status: run.status || "", project,
      scanners: (run.scanners || []).join(", "),
      findings_processed: c.processed ?? "", findings_succeeded: c.succeeded ?? "", findings_failed: c.failed ?? "", findings_skipped: c.skipped ?? "",
      occurrences: run.occurrenceCount ?? 1, failure_reason: run.failureReason || "", run_id: run.id || "",
    };
    if (!match) {
      return { ...base, triggered_by: "", triggered_by_email: "", triggered_via: "", triggered_via_key: "",
        attribution_confidence: "none",
        attribution_evidence: project ? "no scan of this project by a user found in the 24 h before the run (scheduled/automatic scan, or audit data outside the window)" : "run has no project name" };
    }
    const r = match.r;
    const mins = Math.round((done - match.t) / 60000);
    return { ...base, triggered_by: r.actor_name, triggered_by_email: r.actor_email, triggered_via: r.via, triggered_via_key: r.via_key,
      attribution_confidence: "likely",
      attribution_evidence: `${r.event_type} on ${project} by ${r.actor_name} ${mins} min before the run finished (event ${short(r.event_id)})` };
  });
}

// -------------------------------------------------------------- timeline --
/** One person-centric row per thing that happened, from every source. */
export function buildActivity({ audit = [], keys = [], usage = [], userEvents = [], adminEvents = [], aiRuns = [] }) {
  const rows = [];
  const push = (r) => rows.push({
    time: "", person: "", email: "", person_type: "", via: "", via_key: "", confidence: "", action: "", category: "",
    target: "", target_people: "", ip: "", evidence: "", source: "", ref: "", person_id: "", ...r,
  });
  for (const a of audit) push({
    time: a.time, person: a.actor_name, email: a.actor_email, person_type: a.actor_type, person_id: a.actor_user_id,
    via: a.via, via_key: a.via_key, confidence: a.via_confidence, action: a.event_type, category: category(a.event_type),
    target: a.target, target_people: a.target_people, ip: a.ip_address, evidence: a.via_evidence, source: "audit trail", ref: a.event_id,
  });
  for (const k of keys) push({
    time: k.created_at, person: k.created_by_name, email: k.email, person_type: "user", person_id: k.created_by_user_id,
    via: "", action: "api-key.created", category: "API keys", target: `API key ${short(k.api_key_session_id)}`,
    ip: k.last_used_from_ip, confidence: "confirmed", evidence: "IAM offline session (API key) owned by this user; start time = creation",
    source: "API keys", ref: k.api_key_session_id,
  });
  for (const u of usage) push({
    time: u.time, person: u.used_by_name, email: u.used_by_email, person_type: "user", person_id: u.used_by_user_id,
    via: "API key", via_key: u.api_key_session_id, confidence: "confirmed", action: "api-key.used", category: "API keys",
    target: `API key ${short(u.api_key_session_id)}${u.api_key_owner_name && u.api_key_owner_name !== u.used_by_name ? ` (owner ${u.api_key_owner_name})` : ""}`,
    ip: u.ip_address, evidence: "IAM token refresh on the key's offline session", source: "API key usage", ref: u.api_key_session_id,
  });
  for (const e of userEvents) {
    if (e.type === "REFRESH_TOKEN" && e.is_api_key) continue; // already shown as api-key.used
    if (e.type === "REFRESH_TOKEN" || e.type === "CODE_TO_TOKEN") continue; // token plumbing, not a person's action
    push({
      time: e.time, person: e.user_name, email: e.email, person_type: e.user_type, person_id: e.user_id,
      via: e.type === "CLIENT_LOGIN" ? "OAuth client" : "Browser sign-in", confidence: "confirmed",
      action: `sign-in.${e.type.toLowerCase()}${e.error ? " (failed)" : ""}`, category: "Sign-in",
      target: e.client, ip: e.ip_address, evidence: e.error ? `error: ${e.error}` : "IAM user event", source: "IAM user events", ref: e.session_id,
    });
  }
  for (const e of adminEvents) push({
    time: e.time, person: e.actor_name, email: e.actor_email, person_type: e.actor_type, person_id: e.actor_user_id,
    via: e.via, via_key: e.via_key, confidence: e.via_confidence, action: `iam.${String(e.operation).toLowerCase()} ${String(e.resource_type).toLowerCase()}`,
    category: "Identity & access", target: e.resource_path, target_people: e.target_person, ip: e.actor_ip, evidence: e.via_evidence,
    source: "IAM admin events", ref: e.resource_path,
  });
  for (const r of aiRuns) push({
    time: r.time, person: r.triggered_by || "(not attributed)", email: r.triggered_by_email, person_type: r.triggered_by ? "user" : "",
    via: r.triggered_via, via_key: r.triggered_via_key, confidence: r.attribution_confidence,
    action: `ai.${r.origin}`, category: "AI credits", target: `${r.project}${r.findings_processed !== "" ? ` · ${r.findings_processed} findings` : ""}`,
    evidence: r.attribution_evidence, source: "AI history", ref: r.run_id,
  });
  return rows.sort((a, b) => String(b.time).localeCompare(String(a.time)));
}

export function category(eventType = "") {
  const t = String(eventType);
  if (/^(users|role|groups|identity-provider|oauth2-client|mfa|ldap|eula|realm|assignment)\.|cxiam/.test(t)) return "Identity & access";
  if (/^(scans|scan-schedulers|dast-scans)\./.test(t)) return "Scans";
  if (/^(projects|applications)\./.test(t)) return "Projects & applications";
  if (/^(tenant-settings|project-settings|sast-default-configs|data-retention|tenant-webhooks|project-webhooks)\./.test(t)) return "Configuration";
  if (/results?\.update$|^vulnerability\.|^(package|image)\./.test(t)) return "Results triage";
  if (/^(source-code|contributing-developers)\.download|^report\./.test(t)) return "Data export";
  return "Other";
}
