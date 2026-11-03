// Stage 3: security headers (helmet), CORS, images, reset page, dependency fixes.
// The "real browser" part uses a locally installed Chrome (headless) and is
// skipped when none is found.
"use strict";

const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { spawn } = require("node:child_process");

const { startServer, request, api, uploadMedia, fixtures, SERVER_DIR } = require("./helpers");

const PUBLIC_URL = "https://api.autohelp.test";
const APP_ORIGINS = ["https://localhost", "http://localhost", "capacitor://localhost", "ionic://localhost"];

describe("Security headers, CORS, images, reset page", () => {
  let srv;
  let token;
  let logoPath;

  before(async () => {
    srv = await startServer({ env: { PUBLIC_BASE_URL: PUBLIC_URL, WEB_ORIGIN: "https://web.autohelp.test" } });
    const r = await api(srv.base, "POST", "/api/auth/register-company", {
      json: { companyName: "Hdr Co", phone: "+43 660 1234567", address: "A 1, 1010 Wien", email: "hdr@example.test", password: "rightpass1", categories: ["repair"] },
    });
    token = r.json.token;
    const up = await uploadMedia(srv.base, token, [{ field: "logo", data: fixtures.png(64, 64), type: "image/png", name: "logo.png" }]);
    logoPath = new URL(up.json.logoUrl).pathname;
  });
  after(async () => srv.stop());

  test("API responses: helmet headers present, no global CSP, images allowed cross-origin", async () => {
    for (const p of ["/api/health", "/api/companies", "/health", "/"]) {
      const r = await request(srv.base, { path: p, headers: { Origin: "https://localhost" } });
      assert.equal(r.status, 200, p);
      const h = r.headers;
      assert.equal(h["x-powered-by"], undefined, `${p}: x-powered-by hidden`);
      assert.equal(h["x-content-type-options"], "nosniff", p);
      assert.match(h["strict-transport-security"], /max-age=\d+/, p);
      assert.equal(h["x-frame-options"], "SAMEORIGIN", p);
      assert.equal(h["referrer-policy"], "no-referrer", p);
      assert.equal(h["cross-origin-resource-policy"], "cross-origin", p);
      assert.equal(h["content-security-policy"], undefined, `${p}: no global CSP`);
    }
  });

  test("uploaded images: cross-origin allowed, own sandbox CSP, correct type", async () => {
    const r = await request(srv.base, { path: logoPath, headers: { Origin: "capacitor://localhost" } });
    assert.equal(r.status, 200);
    assert.equal(r.headers["content-type"], "image/png");
    assert.equal(r.headers["cross-origin-resource-policy"], "cross-origin");
    assert.equal(r.headers["content-security-policy"], "default-src 'none'; sandbox");
    assert.equal(r.headers["x-content-type-options"], "nosniff");
    assert.ok(r.buf.length > 0);
  });

  test("CORS for the app origins: preflight with Authorization, then the real request", async () => {
    for (const origin of APP_ORIGINS) {
      const pre = await request(srv.base, {
        method: "OPTIONS",
        path: "/api/company/update-profile",
        headers: { Origin: origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type" },
      });
      assert.equal(pre.status, 204, origin);
      assert.equal(pre.headers["access-control-allow-origin"], origin, origin);
      assert.equal(pre.headers["access-control-allow-credentials"], "true", origin);
      assert.match(pre.headers["access-control-allow-headers"], /Authorization/i, origin);
      assert.match(pre.headers["access-control-allow-methods"], /POST/, origin);

      const r = await api(srv.base, "POST", "/api/company/update-profile", { token, json: { servicesText: "x" }, headers: { Origin: origin } });
      assert.equal(r.status, 200, origin);
      assert.equal(r.headers["access-control-allow-origin"], origin, origin);
      assert.match(String(r.headers.vary), /Origin/, origin);
    }
  });

  test("CORS: unknown origins refused (403 JSON), requests without Origin (native) allowed", async () => {
    for (const origin of ["https://evil.example", "http://localhost.evil.example", "null"]) {
      const r = await request(srv.base, { path: "/api/companies", headers: { Origin: origin } });
      assert.deepEqual([r.status, r.json], [403, { ok: false, error: "CORS_NOT_ALLOWED" }], origin);
    }
    assert.equal((await request(srv.base, { path: "/api/companies" })).status, 200);
  });

  test("reset page: strict own CSP with a fresh nonce, script carries it, never cached", async () => {
    const a = await request(srv.base, { path: "/reset-password?token=abc123" });
    const b = await request(srv.base, { path: "/reset-password?token=abc123" });
    assert.equal(a.status, 200);
    const csp = a.headers["content-security-policy"];
    const nonce = (csp.match(/'nonce-([^']+)'/) || [])[1];
    assert.ok(nonce, csp);
    assert.match(csp, /default-src 'none'/);
    assert.doesNotMatch(csp, /unsafe-eval|script-src[^;]*unsafe-inline/);
    assert.ok(a.text.includes(`<script nonce="${nonce}">`), "inline script has the nonce");
    assert.notEqual(nonce, (b.headers["content-security-policy"].match(/'nonce-([^']+)'/) || [])[1], "nonce changes per request");
    assert.equal(a.headers["cache-control"], "no-store");
    assert.equal(a.headers["referrer-policy"], "no-referrer");
    assert.ok(a.text.includes("autohelp:///reset-password?token=abc123"), "deep link for the installed apps unchanged");
  });

  test("reset page: a hostile token can't inject markup", async () => {
    const evil = encodeURIComponent('"></a><script>alert(1)</script>');
    const r = await request(srv.base, { path: `/reset-password?token=${evil}` });
    assert.equal(r.status, 200);
    assert.doesNotMatch(r.text, /<script>alert/);
    assert.equal((r.text.match(/<script/g) || []).length, 1, "only the page's own script");
  });

  test("updated multer: crafted field names are refused cleanly (400 JSON), server keeps running", async () => {
    for (const name of ["a[999999999]", `${"a[b]".repeat(500)}`, "x".repeat(5000)]) {
      const form = new FormData();
      form.append(name, "v");
      form.append("logo", new Blob([fixtures.png(8, 8)], { type: "image/png" }), "l.png");
      const resp = await fetch(`${srv.base}/api/company/upload-media`, { method: "POST", headers: { Authorization: `Bearer ${token}` }, body: form });
      assert.ok([200, 400].includes(resp.status), `${name.slice(0, 20)}: ${resp.status}`);
      const j = await resp.json();
      assert.equal(typeof j.ok, "boolean");
    }
    assert.equal((await request(srv.base, { path: "/api/health" })).status, 200);
  });

  test("updated qs: hostile query strings don't crash or slow the server", async () => {
    const t0 = Date.now();
    for (const q of ["category[999999999]=x", `category${"[a]".repeat(200)}=x`, Array.from({ length: 2000 }, (_, i) => `category[]=${i}`).join("&"), "category=a,b,c&page[__proto__]=1"]) {
      const r = await request(srv.base, { path: `/api/companies?${q}` });
      assert.ok(r.status < 500, `${q.slice(0, 30)}: ${r.status}`);
    }
    assert.ok(Date.now() - t0 < 3000);
    assert.equal((await request(srv.base, { path: "/api/health" })).status, 200);
  });
});

// ---------------------------------------------------------------------------
describe("Fixed dependency versions are installed", () => {
  const installed = (name) => JSON.parse(fs.readFileSync(path.join(SERVER_DIR, "node_modules", name, "package.json"), "utf8")).version;
  const atLeast = (v, min) => {
    const a = v.split(".").map(Number);
    const b = min.split(".").map(Number);
    for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
    return true;
  };
  // minimum versions that fix the npm audit findings of 12.10.2026
  for (const [name, min] of [
    ["express", "4.22.3"],
    ["body-parser", "1.20.6"],
    ["qs", "6.16.0"],
    ["path-to-regexp", "0.1.13"],
    ["proxy-addr", "2.0.8"],
    ["multer", "2.4.0"],
    ["morgan", "1.12.1"],
    ["helmet", "8.3.0"],
  ]) {
    test(`${name} >= ${min}`, () => assert.ok(atLeast(installed(name), min), `${name} ${installed(name)}`));
  }
  test("image-size stays pinned at 2.0.4", () => assert.equal(installed("image-size"), "2.0.4"));
});

// ---------------------------------------------------------------------------
const CHROME = [
  process.env.CHROME_PATH,
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "/usr/bin/google-chrome",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].find((p) => p && fs.existsSync(p));

function runChrome(url) {
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "ah-chrome-"));
  return new Promise((resolve) => {
    const c = spawn(CHROME, ["--headless=new", "--disable-gpu", "--no-first-run", `--user-data-dir=${profile}`, "--enable-logging=stderr", "--v=0", "--virtual-time-budget=3000", "--dump-dom", url]);
    let out = "";
    let err = "";
    c.stdout.on("data", (d) => (out += d));
    c.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => c.kill(), 30000);
    c.on("exit", () => {
      clearTimeout(timer);
      setTimeout(() => fs.rmSync(profile, { recursive: true, force: true }), 500);
      resolve({ dom: out, log: err });
    });
  });
}

describe("Real browser (headless Chrome)", { skip: !CHROME && "no Chrome/Edge found" }, () => {
  let srv;
  let token;
  before(async () => {
    srv = await startServer({ env: { PUBLIC_BASE_URL: "http://127.0.0.1" } });
    const r = await api(srv.base, "POST", "/api/auth/register-company", {
      json: { companyName: "Browser Co", phone: "+43 660 1234567", address: "A 1, 1010 Wien", email: "br@example.test", password: "rightpass1", categories: ["repair"] },
    });
    token = r.json.token;
  });
  after(async () => srv.stop());

  test("reset page: the script runs under its CSP and opens the app link; no CSP violation", async () => {
    const { log } = await runChrome(`${srv.base}/reset-password?token=t0k3n`);
    assert.match(log, /Failed to launch 'autohelp:\/\/\/reset-password\?token=t0k3n'/, "script ran and tried to open the app");
    assert.doesNotMatch(log, /Refused to|Content Security Policy/i);
  });

  test("an uploaded image loads in a page of another origin (as in the Android/iOS WebView)", async () => {
    const up = await uploadMedia(srv.base, token, [{ field: "logo", data: fixtures.png1x1(), type: "image/png", name: "l.png" }]);
    const imgUrl = `${srv.base}${new URL(up.json.logoUrl).pathname}`;
    const page = http.createServer((req, res) => {
      res.setHeader("Content-Type", "text/html");
      res.end(`<html><head><title>WAIT</title></head><body><img src="${imgUrl}" onload="document.title='IMG-LOADED'" onerror="document.title='IMG-BLOCKED'"></body></html>`);
    });
    await new Promise((r) => page.listen(0, "localhost", r));
    try {
      const { dom } = await runChrome(`http://localhost:${page.address().port}/`);
      assert.match(dom, /<title>IMG-LOADED<\/title>/);
    } finally {
      page.close();
    }
  });
});
