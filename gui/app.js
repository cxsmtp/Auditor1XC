// Checkmarx One Auditor - browser UI. All log values are inserted as text (never HTML).
const TOKEN = document.querySelector('meta[name="session-token"]').content;
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/** Tiny DOM builder: h("div", {class:"x", onclick}, child, "text") */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}

// ------------------------------------------------------------ data sets --
const DATASETS = {
  activity: {
    label: "Who did what", time: "time",
    columns: ["time", "person", "email", "action", "target", "target_people", "via", "via_key", "confidence", "ip", "category",
      "evidence", "source", "person_type", "ref", "person_id"],
    hidden: ["evidence", "person_type", "ref", "person_id", "category"],
    facets: ["person", "category", "action", "via", "confidence", "source", "ip"],
    userCols: ["person", "email", "person_id"], ipCols: ["ip"], isError: (r) => /failed/.test(r.action),
  },
  audit_trail: {
    label: "Audit trail", time: "time",
    columns: ["time", "actor_name", "actor_email", "event_type", "target", "target_people", "via", "via_key", "via_confidence", "ip_address",
      "via_evidence", "category", "action", "audit_resource", "actor_type", "actor_user", "actor_user_id", "event_id", "source", "data"],
    hidden: ["via_evidence", "category", "action", "audit_resource", "actor_type", "actor_user", "actor_user_id", "event_id", "source", "data"],
    facets: ["event_type", "category", "actor_name", "via", "via_confidence", "ip_address"],
    userCols: ["actor_name", "actor_email", "actor_user", "actor_user_id"], ipCols: ["ip_address"], isError: null,
  },
  api_keys: {
    label: "API keys", time: "created_at", chart: false,
    columns: ["created_by_name", "email", "created_at", "last_used_at", "last_used_from_ip", "actions_via_key", "action_types", "last_action_at",
      "user_enabled", "api_key_session_id", "created_by_user", "created_by_user_id", "offline_grant_first_created", "offline_grant_last_updated"],
    hidden: ["created_by_user", "created_by_user_id", "offline_grant_first_created", "offline_grant_last_updated"],
    facets: ["created_by_name", "user_enabled", "last_used_from_ip"],
    userCols: ["created_by_name", "email", "created_by_user", "created_by_user_id"], ipCols: ["last_used_from_ip"], isError: null,
  },
  api_key_usage: {
    label: "API key usage", time: "time",
    columns: ["time", "used_by_name", "used_by_email", "ip_address", "api_key_owner_name", "api_key_session_id", "api_key_created_at",
      "event_type", "is_api_key", "error", "used_by_user", "used_by_user_id", "api_key_created_by"],
    hidden: ["event_type", "used_by_user", "used_by_user_id", "api_key_created_by"],
    facets: ["used_by_name", "ip_address", "api_key_owner_name", "api_key_session_id", "is_api_key", "error"],
    userCols: ["used_by_name", "used_by_email", "used_by_user", "used_by_user_id", "api_key_owner_name"], ipCols: ["ip_address"], isError: (r) => !!r.error,
  },
  ai_runs: {
    label: "AI credit usage", time: "time",
    columns: ["time", "project", "origin", "status", "findings_processed", "findings_succeeded", "findings_failed", "findings_skipped",
      "triggered_by", "triggered_by_email", "triggered_via", "triggered_via_key", "attribution_confidence", "attribution_evidence",
      "scanners", "failure_reason", "occurrences", "run_id"],
    hidden: ["findings_skipped", "triggered_via_key", "attribution_evidence", "occurrences", "run_id"],
    facets: ["project", "origin", "status", "triggered_by", "attribution_confidence", "scanners"],
    userCols: ["triggered_by", "triggered_by_email"], ipCols: [], isError: (r) => !!r.failure_reason,
  },
  iam_admin_events: {
    label: "IAM admin events", time: "time",
    columns: ["time", "actor_name", "actor_email", "operation", "resource_type", "target_person", "resource_path", "via", "via_confidence",
      "actor_ip", "actor_client", "error", "via_key", "via_evidence", "actor_type", "actor_user", "actor_user_id", "representation"],
    hidden: ["via_key", "via_evidence", "actor_type", "actor_user", "actor_user_id", "representation"],
    facets: ["operation", "resource_type", "actor_name", "via", "actor_ip", "actor_client", "error"],
    userCols: ["actor_name", "actor_email", "actor_user", "actor_user_id"], ipCols: ["actor_ip"], isError: (r) => !!r.error,
  },
  iam_user_events: {
    label: "IAM user events", time: "time",
    columns: ["time", "user_name", "email", "type", "ip_address", "client", "error", "is_api_key", "session_id", "user_type", "user", "user_id", "details"],
    hidden: ["session_id", "user_type", "user", "user_id"],
    facets: ["type", "user_name", "client", "ip_address", "error", "is_api_key"],
    userCols: ["user_name", "email", "user", "user_id"], ipCols: ["ip_address"], isError: (r) => !!r.error,
  },
  people: {
    label: "People", time: "created_at", chart: false,
    columns: ["name", "email", "username", "type", "enabled", "api_keys", "activity_rows", "client_id", "created_at", "resolved_from", "id"],
    hidden: ["resolved_from"],
    facets: ["type", "enabled", "resolved_from"],
    userCols: ["name", "email", "username", "id"], ipCols: [], isError: null,
  },
};
const JSON_COLS = new Set(["data", "details", "representation"]);
const MONO_COLS = new Set(["ip_address", "actor_ip", "last_used_from_ip", "ip", "api_key_session_id", "session_id", "event_id", "via_key",
  "triggered_via_key", "actor_user_id", "user_id", "used_by_user_id", "created_by_user_id", "person_id", "run_id", "ref", "id"]);
const TIME_COLS = new Set(["time", "created_at", "last_used_at", "last_action_at", "api_key_created_at", "offline_grant_first_created", "offline_grant_last_updated"]);
const CONFIDENCE_COLS = new Set(["via_confidence", "confidence", "attribution_confidence"]);
const LABELS = {
  person: "Person", actor_name: "Person", actor_email: "Email", used_by_name: "Used by", used_by_email: "Email", created_by_name: "Created by",
  api_key_owner_name: "Key owner", api_key_session_id: "API key (session)", via: "Authenticated via", via_key: "API key used",
  via_confidence: "Confidence", via_evidence: "How we know", evidence: "How we know", target_people: "People affected", target_person: "Person affected",
  user_name: "Person", triggered_by: "Triggered by (likely)", triggered_by_email: "Email", triggered_via: "Authenticated via",
  triggered_via_key: "API key used", attribution_confidence: "Confidence", attribution_evidence: "How we know", actions_via_key: "Actions with key",
  action_types: "What the key did", last_action_at: "Last action with key", findings_processed: "Findings processed", activity_rows: "Activity",
  is_api_key: "Is API key", origin: "AI feature",
};
const pretty = (c) => LABELS[c] || c.replace(/_/g, " ").replace(/\bip\b/g, "IP").replace(/\bid\b/g, "ID").replace(/^./, (m) => m.toUpperCase());

// ---------------------------------------------------------------- state --
const state = {
  report: null, users: [], data: null,      // data: {datasetKey: rows[]}
  tab: "overview",
  global: { users: [], ips: [], text: "", from: "", to: "", errorsOnly: false },
  tabs: {},                                  // per dataset UI state
  identity: new Map(),                       // lowercased username/email/id -> Set of all three
};
const tabState = (k) => (state.tabs[k] ||= {
  facets: {}, colFilters: {}, sort: { col: DATASETS[k].time, dir: "desc" }, page: 0, pageSize: 100,
  groupBy: "", hidden: new Set(DATASETS[k].hidden), facetMore: {},
});

// ------------------------------------------------------------- matching --
// A pattern list is comma-separated tokens; "!" prefix excludes; * and ? are wildcards.
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function compileToken(tok, mode) {
  let t = tok.trim(), neg = false;
  if (t.startsWith("!")) { neg = true; t = t.slice(1).trim(); }
  if (!t) return null;
  let exact = mode === "exact";
  if (t.startsWith("=")) { exact = true; t = t.slice(1); }
  const hasWild = /[*?]/.test(t);
  const body = escapeRe(t).replace(/\\\*/g, ".*").replace(/\\\?/g, ".");
  const re = exact || hasWild ? new RegExp(`^${body}$`, "i") : new RegExp(body, "i");
  return { neg, re, raw: tok.trim() };
}
const compileList = (list, mode) => list.map((t) => compileToken(t, mode)).filter(Boolean);
const splitTokens = (s) => String(s || "").split(",").map((x) => x.trim()).filter(Boolean);

/** includes: any positive matches (or no positives); excludes: no negative matches. values = strings of the row. */
function matchTokens(tokens, values) {
  if (!tokens.length) return true;
  const pos = tokens.filter((t) => !t.neg), neg = tokens.filter((t) => t.neg);
  const vals = values.filter((v) => v !== undefined && v !== null && v !== "").map(String);
  if (neg.some((t) => vals.some((v) => t.re.test(v)))) return false;
  return !pos.length || pos.some((t) => vals.some((v) => t.re.test(v)));
}

/** Expand user tokens: a username/email/id matches all three identifiers of that user. */
function compileUserTokens(list) {
  const out = [];
  for (const raw of list) {
    const tok = compileToken(raw, "exact");
    if (!tok) continue;
    out.push(tok);
    for (const u of state.users) {
      if ([u.username, u.email, u.id, u.name].some((v) => v && tok.re.test(v))) {
        for (const v of [u.username, u.email, u.id, u.name]) if (v) out.push({ neg: tok.neg, re: new RegExp(`^${escapeRe(v)}$`, "i"), raw: tok.raw });
      }
    }
  }
  return out;
}

const rowTime = (row, key) => {
  const v = row[DATASETS[key].time];
  if (!v) return NaN;
  if (row.__t === undefined) Object.defineProperty(row, "__t", { value: Date.parse(v), enumerable: false });
  return row.__t;
};
const rowHay = (row) => {
  if (row.__hay === undefined) Object.defineProperty(row, "__hay", { value: Object.values(row).join(" \u0001 ").toLowerCase(), enumerable: false });
  return row.__hay;
};

// ------------------------------------------------------------ filtering --
function globalPredicate(key) {
  const ds = DATASETS[key], g = state.global;
  const users = compileUserTokens(g.users), ips = compileList(g.ips, "exact");
  const text = splitTokens(g.text).map((t) => ({ neg: t.startsWith("!"), q: t.replace(/^!/, "").toLowerCase() })).filter((t) => t.q);
  const from = g.from ? Date.parse(g.from) : NaN, to = g.to ? Date.parse(g.to) : NaN;
  return (r) => {
    if (users.length && !matchTokens(users, ds.userCols.map((c) => r[c]))) return false;
    if (ips.length && !matchTokens(ips, ds.ipCols.map((c) => r[c]))) return false;
    if (text.length) {
      const hay = rowHay(r);
      if (text.some((t) => t.neg && hay.includes(t.q))) return false;
      const pos = text.filter((t) => !t.neg);
      if (pos.length && !pos.some((t) => hay.includes(t.q))) return false;
    }
    if (g.errorsOnly && ds.isError && !ds.isError(r)) return false;
    if (!Number.isNaN(from) || !Number.isNaN(to)) {
      const t = rowTime(r, key);
      if (Number.isNaN(t)) return false;
      if (!Number.isNaN(from) && t < from) return false;
      if (!Number.isNaN(to) && t > to) return false;
    }
    return true;
  };
}

function columnPredicate(key, skipFacet = null) {
  const ts = tabState(key);
  const colTests = Object.entries(ts.colFilters).filter(([, v]) => v.trim())
    .map(([c, v]) => [c, compileList(splitTokens(v), "contains")]);
  const facetTests = Object.entries(ts.facets).filter(([c, f]) => c !== skipFacet && (f.inc.length || f.exc.length));
  return (r) => {
    for (const [c, toks] of colTests) if (!matchTokens(toks, [r[c] ?? ""])) {
      // an empty cell only matches if the user filters for exclusions only
      return false;
    }
    for (const [c, f] of facetTests) {
      const v = String(r[c] ?? "");
      if (f.exc.includes(v)) return false;
      if (f.inc.length && !f.inc.includes(v)) return false;
    }
    return true;
  };
}

const globallyFiltered = (key) => (state.data?.[key] || []).filter(globalPredicate(key));
function filteredRows(key) {
  const base = globallyFiltered(key);
  const col = columnPredicate(key);
  return { base, rows: base.filter(col) };
}

// --------------------------------------------------------------- render --
function render() {
  const has = !!state.data;
  $("#workspace").hidden = !has;
  $("#emptyState").hidden = has;
  $("#saveDataBtn").disabled = !has;
  if (!has) return;
  renderTabs();
  const panel = $("#tabPanel");
  panel.replaceChildren(state.tab === "overview" ? renderOverview() : renderDataset(state.tab));
}

function renderTabs() {
  const tabs = [["overview", "Overview", null]];
  for (const k of Object.keys(DATASETS)) if (state.data[k]) tabs.push([k, DATASETS[k].label, k]);
  $("#tabs").replaceChildren(...tabs.map(([id, label, key]) => {
    const n = key ? filteredRows(key).rows.length : 0;
    const count = key ? h("span", { class: "count" }, `${fmt(n)}${n !== state.data[key].length ? ` / ${fmt(state.data[key].length)}` : ""}`) : null;
    return h("button", { class: "tab", role: "tab", "aria-selected": String(state.tab === id), onclick: () => { state.tab = id; render(); } }, label, count);
  }));
}

const fmt = (n) => Number(n).toLocaleString();
const shortTime = (v) => (v ? String(v).replace("T", " ").replace(/\.\d+/, "").replace(/\+00:00$|Z$/, " UTC") : "");

// ------------------------------------------------------------- overview --
function renderOverview() {
  const d = {};
  for (const k of Object.keys(DATASETS)) d[k] = state.data[k] ? globallyFiltered(k) : null;
  const wrap = h("div");

  const tile = (label, value, sub, onclick) => h("button", { class: "tile", onclick },
    h("div", { class: "label" }, label), h("div", { class: "value" }, value === null ? "—" : fmt(value)), h("div", { class: "sub" }, sub || ""));
  const act = d.activity || [];
  const people = new Set(act.map((r) => r.person).filter((p) => p && !p.startsWith("(")));
  const viaKey = d.audit_trail?.filter((r) => r.via === "API key") ?? null;
  const failed = d.iam_user_events?.filter((r) => r.error) ?? null;
  const ai = d.ai_runs;
  const aiFindings = ai ? ai.reduce((n, r) => n + (Number(r.findings_processed) || 0), 0) : null;
  wrap.append(h("div", { class: "tiles" },
    tile("People active", people.size, `${fmt(state.users.length)} known identities`, () => goTab("people")),
    tile("Actions", d.audit_trail?.length ?? null, "in the audit trail", () => goTab("activity")),
    tile("Actions via API key", viaKey?.length ?? null, viaKey ? `${new Set(viaKey.map((r) => r.actor_name)).size} people, ${new Set(viaKey.map((r) => r.via_key)).size} keys` : "", () => {
      resetTab("audit_trail"); tabState("audit_trail").facets.via = { inc: ["API key"], exc: [] }; goTab("audit_trail");
    }),
    tile("API keys", d.api_keys?.length ?? null, d.api_keys ? `${new Set(d.api_keys.map((r) => r.created_by_name)).size} owners` : "not fetched", () => goTab("api_keys")),
    tile("AI runs (credits)", ai?.length ?? null, ai ? `${fmt(aiFindings)} findings processed` : "not fetched", () => goTab("ai_runs")),
    tile("Failed sign-ins", failed?.length ?? null, "IAM events with errors", () => { state.global.errorsOnly = true; syncGlobalInputs(); goTab("iam_user_events"); }),
  ));

  if (state.report?.attribution && d.audit_trail) {
    const a = state.report.attribution;
    const pct = a.audit_events ? Math.round((a.with_credential / a.audit_events) * 100) : 0;
    wrap.append(h("div", { class: "card note" },
      h("strong", {}, "Attribution: "),
      `${fmt(a.with_credential)} of ${fmt(a.audit_events)} audit events (${pct}%) are linked to the credential used — ${fmt(a.by_api_key)} through an API key. `,
      a.with_credential < a.audit_events
        ? h("span", { class: "muted" }, "The rest have no IAM sign-in/token event in the 30 minutes before them. That usually means IAM event saving is off or its retention is shorter than the time range — the person is still named, only the credential is unknown.")
        : null));
  }

  if (state.report?.sections) {
    const failedSections = Object.entries(state.report.sections).filter(([, s]) => s.status !== "ok");
    if (failedSections.length) {
      wrap.append(h("div", { class: "section-title" }, "Data that could not be fetched"),
        h("div", { class: "findings" }, failedSections.map(([n, s]) => h("div", { class: "finding" },
          h("span", { class: "sev high" }, "missing"), h("div", { class: "title" }, n), h("span"),
          h("div", { class: "detail" }, s.status)))));
    }
  }

  wrap.append(h("div", { class: "section-title" }, "Things worth reviewing",
    h("span", { class: "muted" }, "heuristics to point you at rows, not verdicts — click one to filter")));
  const findings = computeFindings(d);
  wrap.append(findings.length ? h("div", { class: "findings" }, findings.map(renderFinding))
    : h("div", { class: "none" }, "Nothing flagged for the current filters."));

  wrap.append(h("div", { class: "section-title" }, "People", h("span", { class: "muted" }, "click a person to see everything they did")));
  wrap.append(renderPeopleSummary(d));
  return wrap;
}

function renderFinding(f) {
  return h("div", { class: "finding" },
    h("span", { class: `sev ${f.sev}` }, f.sev === "high" ? "high" : f.sev === "info" ? "info" : "review"),
    h("div", { class: "title" }, f.title),
    f.action ? h("button", { class: "btn small", onclick: f.action }, f.actionLabel || "Show rows") : h("span"),
    h("div", { class: "detail" }, f.detail));
}

const DAY = 86_400_000;
const shortId = (s) => (s ? String(s).slice(0, 8) : "");
function computeFindings(d) {
  const out = [];
  const keyActions = (sid) => () => { resetTab("audit_trail"); tabState("audit_trail").colFilters.via_key = `=${sid}`; goTab("audit_trail"); };

  if (d.audit_trail) {
    // which people acted through API keys, and what they did
    const viaKey = d.audit_trail.filter((r) => r.via === "API key" && r.via_key);
    const byKey = new Map();
    for (const r of viaKey) {
      const e = byKey.get(r.via_key) || { person: r.actor_name, email: r.actor_email, rows: [] };
      e.rows.push(r);
      byKey.set(r.via_key, e);
    }
    const keyInfo = new Map((d.api_keys || []).map((k) => [k.api_key_session_id, k]));
    for (const [sid, e] of [...byKey].sort((a, b) => b[1].rows.length - a[1].rows.length).slice(0, 8)) {
      const deletes = e.rows.filter((r) => /delete/i.test(r.event_type)).length;
      const k = keyInfo.get(sid);
      const disabled = k && String(k.user_enabled) === "false";
      out.push({
        sev: disabled ? "high" : deletes ? "review" : "info",
        title: `${e.person}${e.email ? ` <${e.email}>` : ""} performed ${e.rows.length} action(s) with API key ${shortId(sid)}`,
        detail: `${summarize(e.rows, "event_type")}${k ? ` · key created ${shortTime(k.created_at).slice(0, 10)}` : ""}${disabled ? " · OWNER IS DISABLED" : ""} · IPs: ${[...new Set(e.rows.map((r) => r.ip_address).filter(Boolean))].slice(0, 5).join(", ") || "—"}`,
        action: keyActions(sid), actionLabel: "Show these actions",
      });
    }
  }
  if (d.api_key_usage) {
    const byKey = new Map();
    for (const r of d.api_key_usage) {
      if (!r.api_key_session_id) continue;
      const e = byKey.get(r.api_key_session_id) || { ips: new Set(), owner: r.api_key_owner_name || r.used_by_name, n: 0 };
      if (r.ip_address) e.ips.add(r.ip_address);
      e.n++;
      byKey.set(r.api_key_session_id, e);
    }
    for (const [sid, e] of byKey) if (e.ips.size > 1) out.push({
      sev: e.ips.size >= 4 ? "high" : "review",
      title: `API key ${shortId(sid)} of ${e.owner || "unknown user"} used from ${e.ips.size} different IPs`,
      detail: `${e.n} uses · IPs: ${[...e.ips].slice(0, 8).join(", ")}${e.ips.size > 8 ? " …" : ""}. Could be CI runners, or a leaked key.`,
      action: () => { resetTab("api_key_usage"); tabState("api_key_usage").colFilters.api_key_session_id = `=${sid}`; goTab("api_key_usage"); },
    });
  }
  if (d.api_keys) {
    const disabled = d.api_keys.filter((r) => String(r.user_enabled) === "false");
    if (disabled.length) out.push({
      sev: "high", title: `${disabled.length} API key(s) belong to disabled users`,
      detail: `Owners: ${[...new Set(disabled.map((r) => `${r.created_by_name}${r.email ? ` <${r.email}>` : ""}`))].join(", ")}. Keys of disabled users should be revoked.`,
      action: () => { resetTab("api_keys"); tabState("api_keys").facets.user_enabled = { inc: ["false"], exc: [] }; goTab("api_keys"); },
    });
    const stale = d.api_keys.filter((r) => r.last_used_at && Date.now() - Date.parse(r.last_used_at) > 90 * DAY);
    if (stale.length) out.push({
      sev: "review", title: `${stale.length} API key(s) unused for more than 90 days`,
      detail: `Owners: ${[...new Set(stale.map((r) => r.created_by_name))].slice(0, 15).join(", ")}. Unused keys are candidates for revocation.`,
      action: () => { resetTab("api_keys"); tabState("api_keys").sort = { col: "last_used_at", dir: "asc" }; goTab("api_keys"); },
      actionLabel: "Show oldest first",
    });
    for (const [owner, n] of countBy(d.api_keys, "created_by_name")) if (n >= 5) out.push({
      sev: "review", title: `${owner} has ${n} API keys`,
      detail: "Many keys per person make it hard to know which integration uses which key.",
      action: () => { resetTab("api_keys"); filterUser(owner); goTab("api_keys"); },
    });
  }
  if (d.ai_runs?.length) {
    const byPerson = countBy(d.ai_runs, "triggered_by");
    const unattributed = d.ai_runs.filter((r) => !r.triggered_by).length;
    out.push({
      sev: "info", title: `${d.ai_runs.length} AI Triage/Remediation run(s) consumed AI credits`,
      detail: `Likely triggered by: ${byPerson.filter(([p]) => p).slice(0, 6).map(([p, n]) => `${p} ×${n}`).join(", ") || "—"}${unattributed ? ` · ${unattributed} not attributable (scheduled/automatic scans)` : ""}. Credit amounts per run are not exposed by the API.`,
      action: () => { resetTab("ai_runs"); tabState("ai_runs").groupBy = "triggered_by"; goTab("ai_runs"); }, actionLabel: "Show by person",
    });
  }
  if (d.iam_user_events) {
    const failed = d.iam_user_events.filter((r) => r.error);
    const byIp = new Map();
    for (const r of failed) {
      if (!r.ip_address) continue;
      const e = byIp.get(r.ip_address) || { users: new Set(), n: 0 };
      e.users.add(r.user_name || r.user_id); e.n++;
      byIp.set(r.ip_address, e);
    }
    for (const [ip, e] of byIp) if (e.users.size >= 3) out.push({
      sev: "high", title: `Failed sign-ins for ${e.users.size} different people from ${ip}`,
      detail: `${e.n} failures (${[...e.users].slice(0, 6).join(", ")}). One IP failing against many accounts can indicate password spraying.`,
      action: () => { state.global.errorsOnly = true; state.global.ips = [ip]; syncGlobalInputs(); goTab("iam_user_events"); },
    });
    for (const [user, n] of countBy(failed, "user_name")) if (n >= 5) out.push({
      sev: "review", title: `${n} failed sign-ins for ${user}`,
      detail: "Repeated failures for one account: forgotten password, a misconfigured integration, or guessing.",
      action: () => { state.global.errorsOnly = true; filterUser(user); goTab("iam_user_events"); },
    });
  }
  if (d.audit_trail) {
    const deletes = d.audit_trail.filter((r) => /delete/i.test(r.action) || /\.delete$/i.test(r.event_type));
    if (deletes.length) {
      const byUser = countBy(deletes, "actor_name");
      out.push({
        sev: "info", title: `${fmt(deletes.length)} delete action(s) by ${byUser.length} people`,
        detail: `${byUser.slice(0, 8).map(([u, n]) => `${u || "unknown"} ×${n}`).join(", ")}${byUser.length > 8 ? " …" : ""} · ${summarize(deletes, "event_type")}`,
        action: () => { resetTab("audit_trail"); tabState("audit_trail").colFilters.event_type = "*delete*"; tabState("audit_trail").groupBy = "actor_name"; goTab("audit_trail"); },
        actionLabel: "Show by person",
      });
    }
    const PRIV = /^(role\.|users\.(assign|unassign|create|delete)|groups\.(assign|unassign)|oauth2-client\.|identity-provider\.|realm\.update|mfa\.delete|ldap\.|tenant-settings\.)|cxiam\.(user|role|oauth2-client|identity-provider|realm)/i;
    const priv = d.audit_trail.filter((r) => PRIV.test(r.event_type));
    if (priv.length) out.push({
      sev: "review", title: `${priv.length} access-control / identity change(s)`,
      detail: `${summarize(priv, "event_type")} · by ${[...new Set(priv.map((r) => r.actor_name))].slice(0, 10).join(", ")}`,
      action: () => { resetTab("audit_trail"); tabState("audit_trail").facets.category = { inc: ["Identity & access"], exc: [] }; goTab("audit_trail"); },
    });
    const unknown = d.audit_trail.filter((r) => /^unknown user/.test(r.actor_name));
    if (unknown.length) out.push({
      sev: "review", title: `${unknown.length} action(s) by IDs that could not be resolved to a person`,
      detail: "IAM did not return these users and no event named them. They may belong to another identity provider or a system process.",
      action: () => { resetTab("audit_trail"); tabState("audit_trail").colFilters.actor_name = "unknown user*"; goTab("audit_trail"); },
    });
  }
  const rank = { high: 0, review: 1, info: 2 };
  return out.sort((a, b) => rank[a.sev] - rank[b.sev]);
}
function countBy(rows, col) {
  const m = new Map();
  for (const r of rows) m.set(r[col] ?? "", (m.get(r[col] ?? "") || 0) + 1);
  return [...m].sort((a, b) => b[1] - a[1]);
}
const summarize = (rows, col) => countBy(rows, col).slice(0, 5).map(([v, n]) => `${v || "(empty)"} ×${n}`).join(", ");

/** One row per person, built from the merged timeline so every source counts. */
function renderPeopleSummary(d) {
  const rows = new Map();
  for (const r of d.activity || []) {
    if (!r.person) continue;
    const e = rows.get(r.person) || { person: r.person, email: r.email || "", type: r.person_type || "", actions: 0, viaKey: 0, keysUsed: new Set(),
      deletes: 0, keysCreated: 0, ai: 0, failures: 0, ips: new Set(), last: "" };
    if (!e.email && r.email) e.email = r.email;
    if (r.source === "audit trail") { e.actions++; if (/delete/i.test(r.action)) e.deletes++; }
    if (r.via === "API key" && r.source === "audit trail") { e.viaKey++; if (r.via_key) e.keysUsed.add(r.via_key); }
    if (r.action === "api-key.created") e.keysCreated++;
    if (r.source === "AI history") e.ai++;
    if (/failed/.test(r.action)) e.failures++;
    if (r.ip) e.ips.add(r.ip);
    if (r.time && r.time > e.last) e.last = r.time;
    rows.set(r.person, e);
  }
  const list = [...rows.values()].sort((a, b) => b.actions - a.actions || b.last.localeCompare(a.last));
  if (!list.length) return h("div", { class: "none" }, "No activity for the current filters.");
  const cols = [["person", "Person"], ["email", "Email"], ["type", "Type"], ["actions", "Actions"], ["viaKey", "…via API key"], ["keysUsed", "Keys used"],
    ["deletes", "Deletes"], ["keysCreated", "Keys created"], ["ai", "AI runs"], ["failures", "Failed sign-ins"], ["ips", "IPs"], ["last", "Last activity"]];
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, cols.map(([, l]) => h("th", {}, l)))),
    h("tbody", {}, list.map((e) => h("tr", { onclick: () => { filterUser(e.person); goTab("activity"); }, title: `Everything ${e.person} did` },
      cols.map(([c]) => {
        const v = e[c] instanceof Set ? e[c].size : e[c];
        const num = typeof v === "number";
        return h("td", { class: num ? "num" : "" }, c === "last" ? shortTime(v) : num ? fmt(v) : v);
      })))),
  ));
}

// -------------------------------------------------------------- dataset --
function renderDataset(key) {
  const ds = DATASETS[key], ts = tabState(key);
  const { base, rows } = filteredRows(key);
  const sorted = sortRows(rows, ts.sort);
  const wrap = h("div");

  // toolbar
  const visibleCols = ds.columns.filter((c) => !ts.hidden.has(c));
  const groupSel = h("select", { "aria-label": "Group by", onchange: (e) => { ts.groupBy = e.target.value; ts.page = 0; render(); } },
    h("option", { value: "" }, "No grouping"), ds.columns.filter((c) => !JSON_COLS.has(c)).map((c) => h("option", { value: c, selected: ts.groupBy === c }, `Group by ${pretty(c)}`)));
  const colsMenu = columnsMenu(key);
  wrap.append(h("div", { class: "toolbar" },
    h("span", { class: "count" }, `${fmt(rows.length)} of ${fmt(state.data[key].length)} rows`),
    hasTabFilters(key) ? h("button", { class: "btn small", onclick: () => { resetTab(key); render(); } }, "Clear tab filters") : null,
    h("span", { class: "spacer" }),
    groupSel, colsMenu,
    h("button", { class: "btn", onclick: () => download(`${key}.csv`, toCsv(sorted, visibleCols), "text/csv") }, "Export CSV"),
    h("button", { class: "btn", onclick: () => download(`${key}.json`, JSON.stringify(sorted, null, 2), "application/json") }, "Export JSON"),
  ));

  const main = h("div");
  if (ds.chart !== false) main.append(renderChart(key, rows));
  main.append(ts.groupBy ? renderGrouped(key, sorted) : renderTable(key, sorted, visibleCols));
  wrap.append(h("div", { class: "layout" }, renderFacets(key, base), main));
  return wrap;
}

const hasTabFilters = (key) => {
  const ts = tabState(key);
  return Object.values(ts.colFilters).some((v) => v.trim()) || Object.values(ts.facets).some((f) => f.inc.length || f.exc.length);
};
function resetTab(key) { const ts = tabState(key); ts.facets = {}; ts.colFilters = {}; ts.page = 0; ts.groupBy = ""; }

function sortRows(rows, { col, dir }) {
  if (!col) return rows;
  const m = dir === "asc" ? 1 : -1;
  const num = (v) => (typeof v === "number" ? v : NaN);
  return [...rows].sort((a, b) => {
    const x = a[col] ?? "", y = b[col] ?? "";
    if (!Number.isNaN(num(x)) && !Number.isNaN(num(y))) return (x - y) * m;
    if (x === "" && y !== "") return 1;
    if (y === "" && x !== "") return -1;
    return String(x).localeCompare(String(y), undefined, { numeric: true }) * m;
  });
}

function columnsMenu(key) {
  const ds = DATASETS[key], ts = tabState(key);
  const panel = h("div", { class: "menu-panel", hidden: true },
    ds.columns.map((c) => h("label", {}, h("input", {
      type: "checkbox", checked: !ts.hidden.has(c),
      onchange: (e) => { e.target.checked ? ts.hidden.delete(c) : ts.hidden.add(c); render(); },
    }), pretty(c))));
  const btn = h("button", { class: "btn", "aria-haspopup": "true", onclick: (e) => { e.stopPropagation(); panel.hidden = !panel.hidden; } }, "Columns ▾");
  return h("div", { class: "menu" }, btn, panel);
}

function renderFacets(key, base) {
  const ds = DATASETS[key], ts = tabState(key);
  const box = h("div", { class: "facets" });
  for (const col of ds.facets) {
    const f = (ts.facets[col] ||= { inc: [], exc: [] });
    const pool = base.filter(columnPredicate(key, col));
    const counts = countBy(pool, col);
    for (const v of [...f.inc, ...f.exc]) if (!counts.some(([x]) => String(x) === v)) counts.push([v, 0]);
    if (!counts.length || (counts.length === 1 && counts[0][0] === "" && !f.inc.length)) continue;
    const limit = ts.facetMore[col] ? 60 : 7;
    const toggle = (v, mode) => {
      const s = String(v);
      const inList = f[mode].includes(s);
      f.inc = f.inc.filter((x) => x !== s); f.exc = f.exc.filter((x) => x !== s);
      if (!inList) f[mode].push(s);
      ts.page = 0; render();
    };
    box.append(h("div", { class: "facet" },
      h("h4", {}, pretty(col), f.inc.length || f.exc.length ? h("button", { class: "more", onclick: () => { ts.facets[col] = { inc: [], exc: [] }; render(); } }, "reset") : null),
      counts.slice(0, limit).map(([v, n]) => {
        const s = String(v), inc = f.inc.includes(s), exc = f.exc.includes(s);
        return h("div", { class: "facet-row" },
          h("span", { class: `val${inc ? " inc" : ""}${exc ? " exc" : ""}`, title: `${s || "(empty)"} — click to include`, role: "button", tabindex: "0",
            onclick: () => toggle(v, "inc"), onkeydown: (e) => { if (e.key === "Enter") toggle(v, "inc"); } }, s || "(empty)"),
          h("span", { class: "n" }, fmt(n)),
          h("button", { class: "x", title: exc ? "Stop excluding" : "Exclude this value", "aria-label": `Exclude ${s}`, onclick: () => toggle(v, "exc") }, exc ? "↺" : "⊘"));
      }),
      counts.length > 7 ? h("button", { class: "more", onclick: () => { ts.facetMore[col] = !ts.facetMore[col]; render(); } },
        ts.facetMore[col] ? "show fewer" : `show more (${counts.length - 7})`) : null));
  }
  return box;
}

function renderTable(key, rows, cols) {
  const ts = tabState(key);
  const pages = Math.max(1, Math.ceil(rows.length / ts.pageSize));
  ts.page = Math.min(ts.page, pages - 1);
  const slice = rows.slice(ts.page * ts.pageSize, (ts.page + 1) * ts.pageSize);

  const head = h("tr", {}, cols.map((c) => h("th", {
    class: "sortable", title: "Sort",
    onclick: () => { ts.sort = { col: c, dir: ts.sort.col === c && ts.sort.dir === "desc" ? "asc" : "desc" }; render(); },
  }, pretty(c), ts.sort.col === c ? h("span", { class: "dir" }, ts.sort.dir === "asc" ? "▲" : "▼") : null)));
  const filterRow = h("tr", { class: "colfilters" }, cols.map((c) => h("th", {}, h("input", {
    value: ts.colFilters[c] || "", placeholder: "filter…", "aria-label": `Filter ${pretty(c)}`, "data-col": c,
    title: "contains · comma = OR · ! excludes · = exact · * ? wildcards",
    oninput: debounce((e) => { ts.colFilters[c] = e.target.value; ts.page = 0; render(); restoreFocus(`input[data-col="${c}"]`); }, 250),
  }))));
  const body = h("tbody", {}, slice.map((r) => h("tr", { onclick: () => openDrawer(key, r) },
    cols.map((c) => cell(c, r[c])))));
  const table = h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, head, filterRow), body));
  if (!rows.length) body.append(h("tr", {}, h("td", { colspan: cols.length, class: "none" }, "No rows match the current filters.")));

  const pager = h("div", { class: "pager" },
    h("label", {}, "Rows per page ", h("select", { onchange: (e) => { ts.pageSize = +e.target.value; ts.page = 0; render(); } },
      [50, 100, 250, 500, 1000].map((n) => h("option", { value: n, selected: n === ts.pageSize }, n)))),
    h("button", { class: "btn small", disabled: ts.page === 0, onclick: () => { ts.page = 0; render(); } }, "«"),
    h("button", { class: "btn small", disabled: ts.page === 0, onclick: () => { ts.page--; render(); } }, "‹ Prev"),
    h("span", {}, `Page ${ts.page + 1} of ${pages}`),
    h("button", { class: "btn small", disabled: ts.page >= pages - 1, onclick: () => { ts.page++; render(); } }, "Next ›"),
    h("button", { class: "btn small", disabled: ts.page >= pages - 1, onclick: () => { ts.page = pages - 1; render(); } }, "»"));
  return h("div", {}, table, pager);
}

function cell(col, v) {
  let text = v === undefined || v === null ? "" : String(v);
  if (TIME_COLS.has(col)) text = shortTime(text);
  if (JSON_COLS.has(col) && (text === "{}" || text === "[]")) text = "";
  const cls = [MONO_COLS.has(col) || JSON_COLS.has(col) ? "mono" : ""].join(" ");
  if (col === "error" && text) return h("td", { title: text }, h("span", { class: "flag" }, text));
  if (CONFIDENCE_COLS.has(col) && text) return h("td", {}, h("span", { class: `conf conf-${text}` }, text));
  if (col === "user_enabled" && text === "false") return h("td", {}, h("span", { class: "flag" }, "disabled"));
  return h("td", { class: cls, title: text.length > 40 ? text.slice(0, 500) : null }, text);
}

function renderGrouped(key, rows) {
  const ds = DATASETS[key], ts = tabState(key), col = ts.groupBy;
  const groups = new Map();
  for (const r of rows) {
    const v = String(r[col] ?? "");
    const g = groups.get(v) || { value: v, count: 0, first: "", last: "", users: new Set(), ips: new Set() };
    g.count++;
    const t = r[ds.time];
    if (t && (!g.first || t < g.first)) g.first = t;
    if (t && (!g.last || t > g.last)) g.last = t;
    for (const c of ds.userCols.slice(0, 1)) if (r[c]) g.users.add(r[c]);
    for (const c of ds.ipCols) if (r[c]) g.ips.add(r[c]);
    groups.set(v, g);
  }
  const list = [...groups.values()].sort((a, b) => b.count - a.count);
  const drill = (v) => {
    if (ds.facets.includes(col)) ts.facets[col] = { inc: [v], exc: [] };
    else ts.colFilters[col] = `=${v}`;
    ts.groupBy = ""; render();
  };
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, [pretty(col), "Rows", "Distinct users", "Distinct IPs", "First", "Last"].map((l) => h("th", {}, l)))),
    h("tbody", {}, list.map((g) => h("tr", { onclick: () => drill(g.value), title: "Show these rows" },
      h("td", {}, g.value || "(empty)"), h("td", { class: "num" }, fmt(g.count)), h("td", { class: "num" }, fmt(g.users.size)),
      h("td", { class: "num" }, fmt(g.ips.size)), h("td", {}, shortTime(g.first)), h("td", {}, shortTime(g.last)))))));
}

// ---------------------------------------------------------------- chart --
// Single series (rows per day) -> one accent hue, no legend, hover tooltip, click a bar to zoom to that day.
function renderChart(key, rows) {
  const ds = DATASETS[key];
  const counts = new Map();
  let min = Infinity, max = -Infinity, outside = 0;
  // keep the axis to the fetched window: e.g. API keys created months earlier would squash it
  const winFrom = state.report?.from ? Math.floor(Date.parse(state.report.from) / DAY) : -Infinity;
  const winTo = state.report?.to ? Math.floor(Date.parse(state.report.to) / DAY) : Infinity;
  for (const r of rows) {
    const t = rowTime(r, key);
    if (Number.isNaN(t)) continue;
    const day = Math.floor(t / DAY);
    if (day < winFrom || day > winTo) { outside++; continue; }
    counts.set(day, (counts.get(day) || 0) + 1);
    if (day < min) min = day;
    if (day > max) max = day;
  }
  const card = h("div", { class: "chart-card" });
  const title = h("div", { class: "chart-title" }, h("span", {}, `${DATASETS[key].label} per day (by ${pretty(ds.time).toLowerCase()}, UTC)`),
    state.global.from || state.global.to ? h("button", { class: "more", onclick: () => { state.global.from = state.global.to = ""; syncGlobalInputs(); render(); } }, "reset time zoom") : h("span", { class: "muted" }, "click a bar to zoom to that day"));
  card.append(title);
  if (!counts.size) { card.append(h("div", { class: "none" }, outside ? `${fmt(outside)} rows fall outside the fetched time range.` : "No dated rows.")); return card; }
  if (outside) title.firstChild.append(h("span", { class: "muted" }, ` · ${fmt(outside)} rows outside the fetched range not charted`));

  const days = [];
  for (let d = min; d <= max; d++) days.push([d, counts.get(d) || 0]);
  const W = 1000, H = 110, padL = 0, padB = 0, padT = 6;
  const peak = Math.max(...days.map(([, n]) => n));
  const niceMax = niceCeil(peak);
  const bw = (W - padL) / days.length;
  const gap = days.length > 1 ? Math.min(2, bw * 0.2) : 0;
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `${DATASETS[key].label}: ${fmt(rows.length)} rows over ${days.length} days, peak ${fmt(peak)} per day`);
  const el = (tag, attrs) => { const e = document.createElementNS(ns, tag); for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v); return e; };
  const yaxis = h("div", { class: "yaxis", "aria-hidden": "true" });
  for (const frac of niceMax >= 2 ? [0, 0.5, 1] : [0, 1]) {
    const y = padT + (H - padT - padB) * (1 - frac);
    svg.append(el("line", { x1: padL, x2: W, y1: y, y2: y, class: "gridline", "vector-effect": "non-scaling-stroke" }));
    yaxis.append(h("span", { style: `top:${(y / H) * 100}%` }, fmt(Math.round(niceMax * frac))));
  }
  const tip = $("#tooltip");
  days.forEach(([d, n], i) => {
    const x = padL + i * bw + gap / 2, w = Math.max(1, bw - gap);
    const bh = n ? Math.max(2, (H - padT - padB) * (n / niceMax)) : 0;
    const y = H - padB - bh;
    // hit target is the full column height, larger than the mark
    const hit = el("rect", { x: padL + i * bw, y: padT, width: bw, height: H - padT - padB, fill: "transparent", style: "cursor:pointer" });
    const bar = el("path", { d: roundedTop(x, y, w, bh, Math.min(4, w / 2)), class: "bar" });
    const label = new Date(d * DAY).toISOString().slice(0, 10);
    const show = (e) => { bar.classList.add("hover"); tip.hidden = false; tip.textContent = `${label} · ${fmt(n)} rows`; tip.style.left = `${e.clientX + 12}px`; tip.style.top = `${e.clientY - 28}px`; };
    const hide = () => { bar.classList.remove("hover"); tip.hidden = true; };
    const zoom = () => { hide(); state.global.from = toLocalInput(new Date(d * DAY)); state.global.to = toLocalInput(new Date((d + 1) * DAY - 1000)); syncGlobalInputs(); render(); };
    for (const t of [hit, bar]) { t.addEventListener("mousemove", show); t.addEventListener("mouseleave", hide); t.addEventListener("click", zoom); }
    if (bh) svg.append(bar);
    svg.append(hit);
  });
  card.append(h("div", { class: "chart-body" }, yaxis, svg),
    h("div", { class: "xaxis" }, h("span", {}, new Date(min * DAY).toISOString().slice(0, 10)),
      h("span", {}, `peak ${fmt(peak)}/day`), h("span", {}, new Date(max * DAY).toISOString().slice(0, 10))));
  return card;
}
function niceCeil(v) {
  if (v <= 5) return Math.max(2, v % 2 ? v + 1 : v);
  const p = 10 ** Math.floor(Math.log10(v));
  return [1, 2, 2.5, 5, 10].map((m) => m * p).find((x) => x >= v);
}
function roundedTop(x, y, w, hgt, r) {
  if (hgt <= 0) return "";
  r = Math.min(r, hgt);
  return `M${x},${y + hgt}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + hgt}Z`;
}

// --------------------------------------------------------------- drawer --
function openDrawer(key, row) {
  const ds = DATASETS[key];
  $("#drawerTitle").textContent = `${ds.label} — details`;
  const kv = h("div", { class: "kv" });
  let personButtons = false;
  for (const c of ds.columns) {
    const v = row[c];
    const actions = [];
    if (ds.userCols.includes(c) && v && !personButtons && (personButtons = true)) actions.push(["Everything this person did", () => { filterUser(v); closeDrawer(); goTab("activity"); }],
      ["Filter to this person", () => { filterUser(v); render(); }], ["Exclude", () => { filterUser(`!${v}`); render(); }]);
    if ((c === "via_key" || c === "triggered_via_key") && v && state.data.audit_trail) {
      actions.push(["All actions with this key", () => { resetTab("audit_trail"); tabState("audit_trail").colFilters.via_key = `=${v}`; closeDrawer(); goTab("audit_trail"); }]);
    }
    if (ds.ipCols.includes(c) && v) actions.push(["Filter to this IP", () => { state.global.ips = [String(v)]; syncGlobalInputs(); render(); }],
      ["Exclude IP", () => { state.global.ips.push(`!${v}`); syncGlobalInputs(); render(); }]);
    if (ds.facets.includes(c) && !ds.userCols.includes(c) && !ds.ipCols.includes(c) && v !== "") {
      const f = (tabState(key).facets[c] ||= { inc: [], exc: [] });
      actions.push(["Only this", () => { f.inc = [String(v)]; f.exc = []; render(); }], ["Exclude", () => { f.exc.push(String(v)); render(); }]);
    }
    if (c === "api_key_session_id" && v && state.data.audit_trail) {
      actions.push(["Actions done with this key", () => { resetTab("audit_trail"); tabState("audit_trail").colFilters.via_key = `=${v}`; closeDrawer(); goTab("audit_trail"); }]);
    }
    if ((c === "api_key_session_id" || c === "session_id") && v && state.data.api_key_usage) {
      actions.push(["All uses of this key", () => { resetTab("api_key_usage"); tabState("api_key_usage").colFilters.api_key_session_id = `=${v}`; closeDrawer(); goTab("api_key_usage"); }]);
    }
    let valueNode;
    if (JSON_COLS.has(c) && v) {
      let txt = String(v);
      try { txt = JSON.stringify(JSON.parse(txt), null, 2); } catch { /* keep raw */ }
      valueNode = h("pre", { class: "json" }, txt);
    } else valueNode = h("span", {}, TIME_COLS.has(c) ? `${shortTime(v)}` : String(v ?? ""));
    kv.append(h("div", { class: "k" }, pretty(c)), h("div", { class: "v" }, valueNode,
      actions.length ? h("div", { class: "mini" }, actions.map(([l, fn]) => h("button", { class: "btn small", onclick: fn }, l))) : null));
  }
  const copyBtn = h("button", { class: "btn small", onclick: () => navigator.clipboard?.writeText(JSON.stringify(row, null, 2)).then(() => toast("Row copied")) }, "Copy row as JSON");
  $("#drawerBody").replaceChildren(h("div", { style: "margin-bottom:10px" }, copyBtn), kv);
  $("#drawer").hidden = false;
}
function closeDrawer() { $("#drawer").hidden = true; }

// --------------------------------------------------- global filter inputs --
function tokenBox(boxSel, inputSel, listKey) {
  const box = $(boxSel), input = $(inputSel);
  const add = (raw) => {
    for (const t of splitTokens(raw)) if (!state.global[listKey].includes(t)) state.global[listKey].push(t);
    input.value = ""; syncGlobalInputs(); render();
  };
  input.addEventListener("keydown", (e) => {
    if ((e.key === "Enter" || e.key === ",") && input.value.trim()) { e.preventDefault(); add(input.value); }
    else if (e.key === "Backspace" && !input.value && state.global[listKey].length) { state.global[listKey].pop(); syncGlobalInputs(); render(); }
  });
  input.addEventListener("change", () => { if (input.value.trim()) add(input.value); });
  box.addEventListener("click", (e) => { if (e.target === box) input.focus(); });
}
function renderTokens(boxSel, inputSel, listKey) {
  const box = $(boxSel), input = $(inputSel);
  $$(".token", box).forEach((t) => t.remove());
  for (const [i, t] of state.global[listKey].entries()) {
    box.insertBefore(h("span", { class: `token${t.startsWith("!") ? " exclude" : ""}` }, t,
      h("button", { "aria-label": `Remove ${t}`, onclick: () => { state.global[listKey].splice(i, 1); syncGlobalInputs(); render(); } }, "×")), input);
  }
}
function syncGlobalInputs() {
  renderTokens("#userTokens", "#userInput", "users");
  renderTokens("#ipTokens", "#ipInput", "ips");
  $("#textInput").value = state.global.text;
  $("#gFrom").value = state.global.from;
  $("#gTo").value = state.global.to;
  $("#errorsOnly").checked = state.global.errorsOnly;
}
function filterUser(name) {
  if (!name) return;
  state.global.users = [String(name)];
  syncGlobalInputs();
}
function goTab(t) { state.tab = t; closeDrawer(); render(); window.scrollTo({ top: $("#tabs").offsetTop - 60, behavior: "smooth" }); }

function fillSuggestions() {
  const users = new Set(), ips = new Set();
  for (const u of state.users) { if (u.name) users.add(u.name); if (u.email) users.add(u.email); }
  for (const [k, ds] of Object.entries(DATASETS)) for (const r of state.data?.[k] || []) {
    for (const c of ds.userCols.slice(0, 1)) if (r[c]) users.add(r[c]);
    for (const c of ds.ipCols) if (r[c]) ips.add(r[c]);
  }
  $("#userList").replaceChildren(...[...users].sort().slice(0, 2000).map((v) => h("option", { value: v })));
  $("#ipList").replaceChildren(...[...ips].sort().slice(0, 2000).map((v) => h("option", { value: v })));
}

// ---------------------------------------------------------- saved views --
const VIEWS_KEY = "cxa.views.v1";
const readViews = () => { try { return JSON.parse(localStorage.getItem(VIEWS_KEY) || "{}"); } catch { return {}; } };
const writeViews = (v) => { try { localStorage.setItem(VIEWS_KEY, JSON.stringify(v)); } catch { toast("Could not save view (browser storage blocked)"); } };
function refreshViews(selected = "") {
  const views = readViews();
  $("#viewsSelect").replaceChildren(h("option", { value: "" }, "Saved views…"),
    ...Object.keys(views).sort().map((n) => h("option", { value: n, selected: n === selected }, n)));
  $("#deleteViewBtn").hidden = !selected;
}
function snapshotView() {
  const tabs = {};
  for (const [k, ts] of Object.entries(state.tabs)) tabs[k] = { facets: ts.facets, colFilters: ts.colFilters, sort: ts.sort, groupBy: ts.groupBy, hidden: [...ts.hidden] };
  return { global: state.global, tab: state.tab, tabs };
}
function applyView(v) {
  state.global = { users: [], ips: [], text: "", from: "", to: "", errorsOnly: false, ...structuredClone(v.global) };
  state.tabs = {};
  for (const [k, t] of Object.entries(v.tabs || {})) {
    if (!DATASETS[k]) continue;
    Object.assign(tabState(k), structuredClone({ facets: t.facets, colFilters: t.colFilters, sort: t.sort, groupBy: t.groupBy }), { hidden: new Set(t.hidden || DATASETS[k].hidden) });
  }
  state.tab = state.data?.[v.tab] || v.tab === "overview" ? v.tab : "overview";
  syncGlobalInputs(); render();
}

// ---------------------------------------------------------------- utils --
function toCsv(rows, cols) {
  const esc = (v) => { const s = v === undefined || v === null ? "" : String(v); return /[",\r\n]/.test(s) || /^[=+\-@]/.test(s) ? `"${(/^[=+\-@]/.test(s) ? "'" : "") + s.replace(/"/g, '""')}"` : s; };
  return [cols.join(","), ...rows.map((r) => cols.map((c) => esc(r[c])).join(","))].join("\r\n") + "\r\n";
}
function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = h("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function restoreFocus(sel) { const el = $(sel); if (el) { el.focus(); const n = el.value.length; el.setSelectionRange(n, n); } }
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.hidden = false; clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 2500); }
const pad = (n) => String(n).padStart(2, "0");
function toLocalInput(d) { return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`; }

function decodeKey(key) {
  try {
    const p = JSON.parse(atob(key.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    const m = String(p.iss || "").match(/^https?:\/\/([^/]+)\/auth\/realms\/([^/]+)/);
    return m ? { host: m[1], tenant: m[2], iat: p.iat, exp: p.exp, typ: p.typ } : null;
  } catch { return null; }
}

// --------------------------------------------------------- data loading --
function setData({ report, users, datasets }) {
  state.report = report || null;
  state.users = users || [];
  state.data = datasets || {};
  state.tabs = {};
  if (state.tab !== "overview" && !state.data[state.tab]) state.tab = "overview";
  state.identity.clear();
  const b = $("#tenantBadge");
  b.hidden = !report?.tenant;
  b.textContent = report ? `${report.tenant} · ${shortTime(report.from).slice(0, 10)} → ${shortTime(report.to).slice(0, 10)}` : "";
  $("#connectSummary").textContent = report ? `— ${report.tenant}, fetched ${shortTime(report.fetchedAt || "")}` : "";
  fillSuggestions(); syncGlobalInputs(); render();
}

let controller = null;
async function fetchLogs() {
  const apiKey = $("#apiKey").value.trim();
  if (!apiKey) { $("#fetchStatus").textContent = "Paste an API key first."; $("#apiKey").focus(); return; }
  const sections = $$('input[name="section"]:checked').map((c) => c.value);
  if (!sections.length) { $("#fetchStatus").textContent = "Select at least one data set."; return; }
  const from = $("#fromInput").value, to = $("#toInput").value;
  const body = {
    apiKey, sections, legacyAudit: $("#legacyAudit").checked, keyUserScope: $("#keyUserScope").value,
    from: from ? new Date(from).toISOString() : null, to: to ? new Date(to).toISOString() : null,
    astUrl: $("#astUrl").value.trim() || null, iamUrl: $("#iamUrl").value.trim() || null, tenant: $("#tenant").value.trim() || null,
  };
  const log = $("#progressLog");
  log.hidden = false; log.textContent = "";
  $("#fetchBtn").disabled = true; $("#cancelBtn").hidden = false;
  $("#fetchStatus").textContent = "Fetching…";
  controller = new AbortController();
  let gotResult = false;
  try {
    const res = await fetch("/api/fetch", {
      method: "POST", signal: controller.signal,
      headers: { "Content-Type": "application/json", "X-Session-Token": TOKEN }, body: JSON.stringify(body),
    });
    if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `HTTP ${res.status}`);
    const reader = res.body.getReader(), dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        if (msg.type === "progress") { log.textContent += msg.msg + "\n"; log.scrollTop = log.scrollHeight; }
        else if (msg.type === "error") throw new Error(msg.msg);
        else if (msg.type === "result") {
          gotResult = true;
          setData(msg.data);
          const total = Object.values(msg.data.datasets).reduce((n, r) => n + r.length, 0);
          $("#fetchStatus").textContent = `Done — ${fmt(total)} rows.`;
          $("#connectCard").open = false;
        }
      }
    }
    if (!gotResult) throw new Error("connection closed before the data arrived");
  } catch (e) {
    $("#fetchStatus").textContent = e.name === "AbortError" ? "Cancelled." : `Failed: ${e.message}`;
  } finally {
    $("#fetchBtn").disabled = false; $("#cancelBtn").hidden = true; controller = null;
  }
}

// ----------------------------------------------------------------- init --
function setRange(days) {
  const to = new Date(), from = new Date(to.getTime() - days * DAY);
  $("#fromInput").value = toLocalInput(from);
  $("#toInput").value = toLocalInput(to);
}

function init() {
  // theme
  const savedTheme = (() => { try { return localStorage.getItem("cxa.theme"); } catch { return null; } })();
  if (savedTheme) document.documentElement.dataset.theme = savedTheme;
  $("#themeBtn").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    document.documentElement.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem("cxa.theme", document.documentElement.dataset.theme); } catch { /* ignore */ }
  });

  // connect card
  setRange(30);
  $$("#rangePresets .chip").forEach((b) => b.addEventListener("click", () => {
    $$("#rangePresets .chip").forEach((x) => x.classList.toggle("active", x === b));
    setRange(+b.dataset.days);
  }));
  for (const id of ["#fromInput", "#toInput"]) $(id).addEventListener("input", () => $$("#rangePresets .chip").forEach((x) => x.classList.remove("active")));
  $("#toggleKey").addEventListener("click", () => {
    const k = $("#apiKey");
    k.type = k.type === "password" ? "text" : "password";
    $("#toggleKey").textContent = k.type === "password" ? "Show" : "Hide";
  });
  $("#apiKey").addEventListener("input", () => {
    const v = $("#apiKey").value.trim(), info = $("#keyInfo");
    if (!v) { info.className = "hint"; info.textContent = "The key stays on this computer: it goes only to this local app, which sends it to your Checkmarx One IAM to sign in. It is never saved."; return; }
    const d = decodeKey(v);
    if (!d) { info.className = "hint warn"; info.textContent = "This doesn't look like a Checkmarx One API key (a JWT). If it is, fill in the URL and tenant overrides under Advanced options."; return; }
    info.className = "hint";
    const exp = d.exp ? ` · expires ${new Date(d.exp * 1000).toISOString().slice(0, 10)}` : "";
    const iat = d.iat ? ` · issued ${new Date(d.iat * 1000).toISOString().slice(0, 10)}` : "";
    info.textContent = `Tenant ${d.tenant} on ${d.host}${iat}${exp}`;
    if (d.exp && d.exp * 1000 < Date.now()) { info.className = "hint warn"; info.textContent += " — this key has EXPIRED"; }
  });
  $("#fetchBtn").addEventListener("click", fetchLogs);
  $("#apiKey").addEventListener("keydown", (e) => { if (e.key === "Enter") fetchLogs(); });
  $("#cancelBtn").addEventListener("click", () => controller?.abort());

  // global filters
  tokenBox("#userTokens", "#userInput", "users");
  tokenBox("#ipTokens", "#ipInput", "ips");
  $("#textInput").addEventListener("input", debounce((e) => { state.global.text = e.target.value; render(); }, 250));
  $("#gFrom").addEventListener("change", (e) => { state.global.from = e.target.value; render(); });
  $("#gTo").addEventListener("change", (e) => { state.global.to = e.target.value; render(); });
  $("#errorsOnly").addEventListener("change", (e) => { state.global.errorsOnly = e.target.checked; render(); });
  $("#clearFiltersBtn").addEventListener("click", () => {
    state.global = { users: [], ips: [], text: "", from: "", to: "", errorsOnly: false };
    for (const k of Object.keys(state.tabs)) resetTab(k);
    syncGlobalInputs(); render();
  });

  // saved views
  refreshViews();
  $("#viewsSelect").addEventListener("change", (e) => {
    const name = e.target.value;
    $("#deleteViewBtn").hidden = !name;
    if (name) applyView(readViews()[name]);
  });
  $("#saveViewBtn").addEventListener("click", () => {
    const name = prompt("Name this view (filters, sorting and columns are saved — not the data or the key):", $("#viewsSelect").value || "");
    if (!name) return;
    const views = readViews(); views[name] = snapshotView(); writeViews(views); refreshViews(name); toast(`Saved view “${name}”`);
  });
  $("#deleteViewBtn").addEventListener("click", () => {
    const name = $("#viewsSelect").value;
    if (!name || !confirm(`Delete saved view “${name}”?`)) return;
    const views = readViews(); delete views[name]; writeViews(views); refreshViews();
  });

  // save / open data
  $("#saveDataBtn").addEventListener("click", () => {
    const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
    download(`cx-audit-${state.report?.tenant || "data"}-${stamp}.json`,
      JSON.stringify({ format: "cx-auditor/1", report: state.report, users: state.users, datasets: state.data }), "application/json");
  });
  $("#loadDataInput").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    e.target.value = "";
    if (!file) return;
    try {
      const obj = JSON.parse(await file.text());
      if (obj.format !== "cx-auditor/1" || typeof obj.datasets !== "object") throw new Error("not a file saved by this app");
      for (const k of Object.keys(obj.datasets)) if (!DATASETS[k] || !Array.isArray(obj.datasets[k])) delete obj.datasets[k];
      setData(obj);
      $("#connectCard").open = false;
      toast(`Opened ${file.name}`);
    } catch (err) { toast(`Could not open file: ${err.message}`); }
  });

  document.addEventListener("click", (e) => {
    for (const p of $$(".menu-panel")) if (!p.parentElement.contains(e.target)) p.hidden = true;
  });

  // drawer
  $("#drawerClose").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
  render();
}

init();
