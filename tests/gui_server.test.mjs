// Run: node --test tests/gui_server.test.mjs
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { createServer } from "../cx_auditor_gui.mjs";

let server, port, lastOpts;
const fakeCollect = async (opts, progress) => {
  lastOpts = opts;
  progress("authenticated");
  if (opts.apiKey === "fail") throw new Error("HTTP 401 for https://iam/x: bad token eyJabc.def.ghi");
  return { report: { tenant: "acme" }, users: [{ id: "u1", username: "alice" }], raw: { big: true }, datasets: { audit_trail: [{ time: "t" }] } };
};

before(async () => {
  server = createServer({ token: "T0KEN", collectFn: fakeCollect });
  port = await new Promise((r) => server.listen(0, r));
});
after(() => server.close());

/** Raw request so the Host header is sent exactly as given (fetch() would override it). */
function request({ method = "GET", path = "/", host = `127.0.0.1:${port}`, headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method, path, headers: { Host: host, ...headers } }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}
const fetchApi = (payload, token = "T0KEN") => request({
  method: "POST", path: "/api/fetch", body: JSON.stringify(payload),
  headers: { "Content-Type": "application/json", "X-Session-Token": token },
});
const lines = (body) => body.trim().split("\n").map((l) => JSON.parse(l));

test("serves the page with the session token and a strict CSP", async () => {
  const r = await request();
  assert.equal(r.status, 200);
  assert.match(r.body, /content="T0KEN"/);
  assert.match(r.headers["content-security-policy"], /default-src 'self'/);
  assert.equal((await request({ path: "/app.js" })).status, 200);
});

test("rejects foreign Host headers (DNS rebinding)", async () => {
  assert.equal((await request({ host: "evil.example" })).status, 403);
  assert.equal((await request({ host: `evil.example:${port}` })).status, 403);
  assert.equal((await request({ host: `localhost:${port}` })).status, 200);
});

test("API requires the session token", async () => {
  assert.equal((await fetchApi({ apiKey: "k" }, "")).status, 403);
  assert.equal((await fetchApi({ apiKey: "k" }, "WRONG")).status, 403);
});

test("streams progress then result, without raw data", async () => {
  const r = await fetchApi({ apiKey: "k", sections: ["audit", "keys", "bogus"], keyUserScope: "alice, *@corp.com",
    from: "2026-10-01T00:00:00Z", to: "2026-10-31T00:00:00Z" });
  const msgs = lines(r.body);
  assert.deepEqual(msgs.map((m) => m.type), ["progress", "result"]);
  assert.equal(msgs[1].data.raw, undefined);
  assert.deepEqual([...lastOpts.sections], ["audit", "keys"]);
  assert.equal(lastOpts.start.toISOString(), "2026-10-01T00:00:00.000Z");
  assert.equal(lastOpts.keyUserScope({ username: "alice" }), true);
  assert.equal(lastOpts.keyUserScope({ username: "x", email: "x@corp.com" }), true);
  assert.equal(lastOpts.keyUserScope({ username: "bob", email: "bob@other.com" }), false);
});

test("validates input and redacts tokens in errors", async () => {
  assert.match(lines((await fetchApi({})).body)[0].msg, /API key is required/);
  assert.match(lines((await fetchApi({ apiKey: "k", from: "2026-10-05", to: "2026-10-01" })).body)[0].msg, /after/);
  const err = lines((await fetchApi({ apiKey: "fail" })).body).find((m) => m.type === "error");
  assert.match(err.msg, /<redacted-token>/);
  assert.doesNotMatch(err.msg, /eyJabc/);
});
