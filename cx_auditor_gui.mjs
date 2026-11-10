#!/usr/bin/env node
/**
 * cx_auditor_gui.mjs - local web GUI for the Checkmarx One auditor.
 *
 *   node cx_auditor_gui.mjs            (opens http://127.0.0.1:8787 in your browser)
 *   node cx_auditor_gui.mjs --port 9000 --no-open
 *
 * Node.js 18+, no npm install. A browser page cannot call the Checkmarx One
 * APIs directly (CORS), so this small server makes the calls for the page.
 *
 * Security:
 *  - listens on 127.0.0.1 only;
 *  - rejects requests whose Host header is not this server (DNS-rebinding guard);
 *  - every API call must carry a random per-launch token embedded in the page,
 *    so other websites open in your browser cannot drive it;
 *  - the API key is used in memory for the request and never logged or stored.
 */
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { collect, buildFilters, SECTIONS, isMainModule } from "./cx_auditor.mjs";

// The standalone build replaces `null` below with the contents of gui/ so a single file runs anywhere.
const EMBEDDED_ASSETS = null;
const GUI_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "gui");
function readAsset(name) {
  if (EMBEDDED_ASSETS) return EMBEDDED_ASSETS[name];
  const file = path.join(GUI_DIR, name);
  if (!fs.existsSync(file)) {
    throw new Error(`missing ${file} - keep the gui folder next to cx_auditor_gui.mjs, or use the single-file cx-auditor.mjs`);
  }
  return fs.readFileSync(file, "utf8");
}
const STATIC = {
  "/app.js": ["app.js", "text/javascript; charset=utf-8"],
  "/app.css": ["app.css", "text/css; charset=utf-8"],
};

class Aborted extends Error {}

export function createServer({ token = crypto.randomBytes(24).toString("hex"), collectFn = collect } = {}) {
  let allowedHosts = new Set();

  const server = http.createServer(async (req, res) => {
    const send = (code, body, type = "application/json; charset=utf-8") => {
      res.writeHead(code, {
        "Content-Type": type,
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
      });
      res.end(typeof body === "string" || Buffer.isBuffer(body) ? body : JSON.stringify(body));
    };

    if (!allowedHosts.has(req.headers.host)) return send(403, { error: "forbidden host" });
    const url = new URL(req.url, "http://localhost");

    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      const html = readAsset("index.html").replace("__SESSION_TOKEN__", token);
      return send(200, html, "text/html; charset=utf-8");
    }
    if (req.method === "GET" && STATIC[url.pathname]) {
      const [file, type] = STATIC[url.pathname];
      return send(200, readAsset(file), type);
    }

    if (url.pathname.startsWith("/api/")) {
      const given = Buffer.from(String(req.headers["x-session-token"] || ""));
      const expected = Buffer.from(token);
      if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) {
        return send(403, { error: "invalid session token - reload the page" });
      }
    }

    if (req.method === "POST" && url.pathname === "/api/fetch") {
      let body;
      try {
        body = JSON.parse(await readBody(req, 64 * 1024));
      } catch {
        return send(400, { error: "invalid JSON body" });
      }
      return streamFetch(body, req, res, collectFn);
    }
    return send(404, { error: "not found" });
  });

  const origListen = server.listen.bind(server);
  server.listen = (port, cb) => origListen(port, "127.0.0.1", () => {
    const p = server.address().port;
    allowedHosts = new Set([`127.0.0.1:${p}`, `localhost:${p}`]);
    cb?.(p);
  });
  server.token = token;
  return server;
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** Runs collect() and streams NDJSON: {type:"progress"} lines, then {type:"result"} or {type:"error"}. */
async function streamFetch(body, req, res, collectFn) {
  res.writeHead(200, { "Content-Type": "application/x-ndjson; charset=utf-8", "Cache-Control": "no-store" });
  let closed = false;
  res.on("close", () => { closed = true; });
  const emit = (obj) => { if (!closed) res.write(JSON.stringify(obj) + "\n"); };
  const progress = (msg) => {
    if (closed) throw new Aborted("cancelled");
    emit({ type: "progress", msg });
  };

  try {
    const apiKey = String(body.apiKey || "").trim();
    if (!apiKey) throw new Error("API key is required");
    const end = body.to ? new Date(body.to) : new Date();
    const start = body.from ? new Date(body.from) : new Date(end.getTime() - 30 * 86_400_000);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) throw new Error("invalid date range");
    if (start > end) throw new Error("'From' is after 'To'");
    const sections = (body.sections || SECTIONS).filter((s) => SECTIONS.includes(s));
    if (!sections.length) throw new Error("select at least one data set to fetch");

    const scopeValues = String(body.keyUserScope || "").split(",").map((s) => s.trim()).filter(Boolean);
    const scopeFilter = scopeValues.length ? buildFilters({ user: scopeValues }, []).user : null;

    const result = await collectFn({
      apiKey,
      iamUrl: body.iamUrl || undefined, tenant: body.tenant || undefined, astUrl: body.astUrl || undefined,
      start, end, sections: new Set(sections), legacyAudit: !!body.legacyAudit,
      keyUserScope: scopeFilter ? (u) => [u.username, u.email, u.id].some((v) => v && scopeFilter.some((re) => re.test(v))) : undefined,
    }, progress);
    emit({ type: "result", data: { report: result.report, users: result.users, datasets: result.datasets } });
  } catch (e) {
    if (!(e instanceof Aborted)) emit({ type: "error", msg: redact(e.message) });
  } finally {
    if (!closed) res.end();
  }
}

/** Never echo anything that looks like a JWT (the API key) back to the page or console. */
const redact = (s) => String(s).replace(/eyJ[\w-]+\.[\w-]+\.[\w-]*/g, "<redacted-token>");

function openBrowser(url) {
  const [cmd, args] = process.platform === "darwin" ? ["open", [url]]
    : process.platform === "win32" ? ["cmd", ["/c", "start", "", url]]
    : ["xdg-open", [url]];
  try {
    spawn(cmd, args, { stdio: "ignore", detached: true }).on("error", () => {}).unref();
  } catch { /* user can open the URL manually */ }
}

if (isMainModule(import.meta.url)) {
  const { values: a } = parseArgs({
    options: { port: { type: "string", default: "8787" }, "no-open": { type: "boolean", default: false } },
  });
  const server = createServer();
  const start = (port) => {
    server.once("error", (e) => {
      if (e.code === "EADDRINUSE" && port !== 0) {
        console.error(`port ${port} busy, picking a free one`);
        server.removeAllListeners("listening");  // drop the failed attempt's callback
        start(0);
      }
      else { console.error(e.message); process.exit(1); }
    });
    server.listen(Number(port), (p) => {
      const url = `http://127.0.0.1:${p}/`;
      console.log(`Checkmarx One Auditor GUI running at ${url}\nPress Ctrl+C to stop.`);
      if (!a["no-open"]) openBrowser(url);
    });
  };
  start(a.port);
}
