// The single-file build must be current and must run when copied ALONE into a folder with a space in its name.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("cx-auditor.mjs is rebuilt from current sources", () => {
  execFileSync(process.execPath, [path.join(ROOT, "scripts", "build-standalone.mjs"), "--check"], { stdio: "pipe" });
});

test("cx-auditor.mjs runs on its own from 'New folder' and serves the GUI", async () => {
  const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "cxa-")), "New folder");
  fs.mkdirSync(dir);
  fs.copyFileSync(path.join(ROOT, "cx-auditor.mjs"), path.join(dir, "cx-auditor.mjs"));

  const child = spawn(process.execPath, ["cx-auditor.mjs", "--no-open", "--port", "0"], { cwd: dir });
  try {
    const url = await new Promise((resolve, reject) => {
      let out = "", err = "";
      const t = setTimeout(() => reject(new Error(`no startup line; stdout=${out} stderr=${err}`)), 10000);
      child.stdout.on("data", (d) => {
        out += d;
        const m = out.match(/running at (http:\/\/127\.0\.0\.1:\d+\/)/);
        if (m) { clearTimeout(t); resolve(m[1]); }
      });
      child.stderr.on("data", (d) => (err += d));
      child.on("exit", (code) => reject(new Error(`exited ${code}: ${err}`)));
    });
    const get = (p) => new Promise((resolve, reject) => {
      http.get(new URL(p, url), (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, type: res.headers["content-type"], body }));
      }).on("error", reject);
    });
    const page = await get("/");
    assert.equal(page.status, 200);
    assert.match(page.body, /Checkmarx One Auditor/);
    assert.doesNotMatch(page.body, /__SESSION_TOKEN__/);
    const js = await get("/app.js");
    assert.equal(js.status, 200);
    assert.match(js.type, /javascript/);
    assert.match(js.body, /escapeRe = \(s\) => s\.replace\(\/\[\.\*\+\?\^\$\{\}\(\)\|\[\\\]\\\\\]\/g, "\\\\\$&"\)/);
    assert.equal((await get("/app.css")).status, 200);
  } finally {
    child.kill();
  }
});
