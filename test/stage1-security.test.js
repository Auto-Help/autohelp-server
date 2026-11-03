// Stage 1 security tests: reset links, uploads, rate limits, JSON errors.
// Run: npm test   (local only — never against production)
"use strict";

const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { startServer, startFakeSmtp, smtpEnv, extractResetLink, request, api, uploadMedia, fixtures, SERVER_DIR, waitFor, sleep } = require("./helpers");

const PUBLIC_URL = "https://api.autohelp.test";
const STACK_LEAK = /\bat .+:\d+:\d+|node_modules|[A-Z]:\\|\/data\/|Error:/;

async function registerUser(base, email, password = "secret123") {
  const r = await api(base, "POST", "/api/auth/register-user", {
    json: { firstName: "T", lastName: "U", username: email.split("@")[0], email, password },
  });
  assert.equal(r.status, 200, r.text);
  return r.json;
}

async function registerCompany(base, email, password = "secret123") {
  const r = await api(base, "POST", "/api/auth/register-company", {
    json: { companyName: `Co ${email}`, phone: "+43 660 1234567", address: "Ring 1, 1010 Wien, AT", email, password, categories: ["repair"] },
  });
  assert.equal(r.status, 200, r.text);
  return r.json;
}

// ---------------------------------------------------------------------------
describe("1. Password-reset links cannot be pointed at another host", () => {
  let smtp;
  before(async () => {
    smtp = await startFakeSmtp();
  });
  after(async () => smtp.close());

  async function forgotWithForgedHeaders(srv, email) {
    const before = smtp.mails.length;
    const r = await request(srv.base, {
      method: "POST",
      path: "/api/auth/forgot-password",
      headers: {
        "Content-Type": "application/json",
        Host: "evil.example",
        "X-Forwarded-Host": "attacker.example",
        "X-Forwarded-Proto": "http",
      },
      body: JSON.stringify({ email, lang: "de" }),
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.ok, true);
    assert.ok(await waitFor(() => smtp.mails.length === before + 1), "one mail expected");
    return extractResetLink(smtp.mails.at(-1));
  }

  test("PUBLIC_BASE_URL is used; Host / X-Forwarded-Host are ignored", async () => {
    const srv = await startServer({ env: { ...smtpEnv(smtp), PUBLIC_BASE_URL: `${PUBLIC_URL}/` } });
    try {
      await registerUser(srv.base, "a@example.test");
      const link = await forgotWithForgedHeaders(srv, "a@example.test");
      assert.ok(link?.startsWith(`${PUBLIC_URL}/reset-password?token=`), link);
      assert.doesNotMatch(link, /evil|attacker/);

      // The link still works end to end (old app flow unchanged).
      const token = new URL(link).searchParams.get("token");
      const reset = await api(srv.base, "POST", "/api/auth/reset-password", { json: { token, newPassword: "newpass123" } });
      assert.equal(reset.status, 200);
      const login = await api(srv.base, "POST", "/api/auth/login-user", { json: { email: "a@example.test", password: "newpass123" } });
      assert.equal(login.status, 200);
    } finally {
      await srv.stop();
    }
  });

  test("without PUBLIC_BASE_URL: RENDER_EXTERNAL_URL, never request headers", async () => {
    const srv = await startServer({ env: { ...smtpEnv(smtp), RENDER_EXTERNAL_URL: "https://svc.onrender.test" } });
    try {
      await registerUser(srv.base, "b@example.test");
      const link = await forgotWithForgedHeaders(srv, "b@example.test");
      assert.ok(link.startsWith("https://svc.onrender.test/reset-password?token="), link);
    } finally {
      await srv.stop();
    }
  });

  test("current production config (no PUBLIC_BASE_URL at all): server still starts, uses the known URL, warns", async () => {
    const srv = await startServer({ env: smtpEnv(smtp) });
    try {
      await registerUser(srv.base, "c@example.test");
      const link = await forgotWithForgedHeaders(srv, "c@example.test");
      assert.ok(link.startsWith("https://autohelp-server.onrender.com/reset-password?token="), link);
      assert.match(srv.logs, /PUBLIC_BASE_URL is not set/);
    } finally {
      await srv.stop();
    }
  });

  test("invalid PUBLIC_BASE_URL (javascript:) is ignored with a warning, never used", async () => {
    const srv = await startServer({ env: { ...smtpEnv(smtp), PUBLIC_BASE_URL: "javascript:alert(1)" } });
    try {
      await registerUser(srv.base, "d@example.test");
      const link = await forgotWithForgedHeaders(srv, "d@example.test");
      assert.ok(link.startsWith("https://autohelp-server.onrender.com/"), link);
      assert.match(srv.logs, /PUBLIC_BASE_URL is not a valid/);
    } finally {
      await srv.stop();
    }
  });

  test("reset tokens never appear in the request log", async () => {
    const srv = await startServer({ env: { PUBLIC_BASE_URL: PUBLIC_URL } });
    try {
      const token = "a1b2c3d4e5f6deadbeef00112233445566778899";
      const r = await request(srv.base, { path: `/reset-password?token=${token}&x=1` });
      assert.equal(r.status, 200);
      await new Promise((res) => setTimeout(res, 200));
      assert.match(srv.logs, /GET \/reset-password\?token=\*\*\*&x=1 200/);
      assert.doesNotMatch(srv.logs, new RegExp(token));
    } finally {
      await srv.stop();
    }
  });

  test("at most 3 reset mails per address per hour, same generic answer every time", async () => {
    const srv = await startServer({ env: { ...smtpEnv(smtp), PUBLIC_BASE_URL: PUBLIC_URL } });
    try {
      await registerUser(srv.base, "e@example.test");
      const start = smtp.mails.length;
      const answers = [];
      for (let i = 0; i < 5; i++) {
        // different forged client IPs: the per-address limit must still hold
        const r = await api(srv.base, "POST", "/api/auth/forgot-password", {
          json: { email: "e@example.test" },
          headers: { "X-Forwarded-For": `198.51.100.${i}` },
        });
        answers.push(JSON.stringify([r.status, r.json]));
      }
      await waitFor(() => smtp.mails.length - start >= 3);
      await sleep(300); // no further mails may follow
      assert.equal(smtp.mails.length - start, 3);
      assert.equal(new Set(answers).size, 1, "responses must be identical");
      const unknown = await api(srv.base, "POST", "/api/auth/forgot-password", { json: { email: "nobody@example.test" } });
      assert.equal(JSON.stringify([unknown.status, unknown.json]), answers[0]);
    } finally {
      await srv.stop();
    }
  });
});

// ---------------------------------------------------------------------------
describe("2. Uploads are checked by their real content", () => {
  let srv;
  let token;
  const legacyFiles = {
    "legacy_evil.html": "<html><script>alert(1)</script></html>",
    "legacy_evil.svg": '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>',
    "legacy_noext": "<script>alert(1)</script>",
  };

  before(async () => {
    srv = await startServer({
      env: { PUBLIC_BASE_URL: PUBLIC_URL },
      prepare: ({ uploads, dir }) => {
        // Files an older server version might have stored under client-chosen names.
        for (const [name, body] of Object.entries(legacyFiles)) fs.writeFileSync(path.join(uploads, name), body);
        fs.writeFileSync(path.join(uploads, "legacy_photo.png"), fixtures.jpegExif()); // JPEG bytes, .png name
        fs.writeFileSync(path.join(dir, "outside-secret.txt"), "TOP SECRET");
      },
    });
    token = (await registerCompany(srv.base, "co@example.test")).token;
  });
  after(async () => srv.stop());

  const listUploads = () => fs.readdirSync(srv.uploads).filter((n) => !n.startsWith("legacy_")).sort();

  const ok = [
    ["JPEG (Android/iPhone camera, Exif)", fixtures.jpegExif, "image/jpeg", "IMG_0001.JPG", ".jpg"],
    ["PNG", fixtures.png1x1, "image/png", "shot.png", ".png"],
    ["WebP", fixtures.webp, "image/webp", "x.webp", ".webp"],
    ["GIF", fixtures.gif1x1, "image/gif", "x.gif", ".gif"],
    ["HEIC as iPhone writes it", fixtures.heicIphone, "image/heic", "IMG_0002.HEIC", ".heic"],
    ["HEIF (mif1)", fixtures.heifGeneric, "image/heif", "x.heif", ".heif"],
    ["JPEG sent with a wrong MIME and name (lying extension)", fixtures.jpegExif, "application/octet-stream", "photo.png", ".jpg"],
  ];
  for (const [label, make, type, name, ext] of ok) {
    test(`accepts ${label} -> stored as ${ext}`, async () => {
      const r = await uploadMedia(srv.base, token, [{ field: "images", data: make(), type, name }]);
      assert.equal(r.status, 200, r.text);
      const url = r.json.images.at(-1);
      assert.ok(url.startsWith(`${PUBLIC_URL}/uploads/`), url);
      assert.ok(url.endsWith(ext), url);
      const file = decodeURIComponent(url.split("/uploads/")[1]);
      const got = await request(srv.base, { path: `/uploads/${encodeURIComponent(file)}` });
      assert.equal(got.status, 200);
      assert.equal(got.headers["x-content-type-options"], "nosniff");
      assert.match(got.headers["content-security-policy"], /sandbox/);
      assert.ok(got.headers["content-type"].startsWith("image/"), got.headers["content-type"]);
      // reset gallery so the 3-image cap doesn't interfere with the next case
      await api(srv.base, "POST", "/api/company/update-profile", { token, json: { imagesJson: "[]" } });
    });
  }

  const bad = [
    ["HTML pretending to be PNG", Buffer.from("<html><script>alert(1)</script></html>"), "image/png", "x.png"],
    ["SVG with script", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'), "image/svg+xml", "x.svg"],
    ["SVG renamed to .png", Buffer.from('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>'), "image/png", "x.png"],
    ["Windows executable", Buffer.concat([Buffer.from("MZ"), Buffer.alloc(200)]), "image/jpeg", "x.jpg"],
    ["PDF", Buffer.from("%PDF-1.7\n%âãÏÓ\n1 0 obj\n"), "image/jpeg", "x.jpg"],
    ["empty file", Buffer.alloc(0), "image/png", "x.png"],
    ["AVIF (not supported before either)", fixtures.avif(), "image/avif", "x.avif"],
  ];
  for (const [label, data, type, name] of bad) {
    test(`rejects ${label} with 400 JSON, writes nothing`, async () => {
      const beforeFiles = listUploads();
      const r = await uploadMedia(srv.base, token, [{ field: "images", data, type, name }]);
      assert.equal(r.status, 400, r.text);
      assert.deepEqual(r.json, { ok: false, error: "ONLY_IMAGES_ALLOWED" });
      assert.deepEqual(listUploads(), beforeFiles);
    });
  }

  test("one bad file rejects the whole request (no half upload)", async () => {
    const beforeFiles = listUploads();
    const r = await uploadMedia(srv.base, token, [
      { field: "logo", data: fixtures.png1x1(), type: "image/png", name: "logo.png" },
      { field: "images", data: Buffer.from("<html>"), type: "image/png", name: "x.png" },
    ]);
    assert.equal(r.status, 400);
    assert.deepEqual(listUploads(), beforeFiles);
  });

  test("polyglot (PNG header + HTML, named .html) is stored and served only as image/png", async () => {
    const data = Buffer.concat([fixtures.png1x1(), Buffer.from("<html><script>alert(1)</script></html>")]);
    const r = await uploadMedia(srv.base, token, [{ field: "logo", data, type: "text/html", name: "evil.html" }]);
    assert.equal(r.status, 200, r.text);
    assert.ok(r.json.logoUrl.endsWith(".png"), r.json.logoUrl);
    const file = r.json.logoUrl.split("/uploads/")[1];
    const got = await request(srv.base, { path: `/uploads/${file}` });
    assert.equal(got.headers["content-type"], "image/png");
    assert.equal(got.headers["x-content-type-options"], "nosniff");
  });

  test("file over 8 MB -> 413 JSON FILE_TOO_LARGE, nothing written", async () => {
    const beforeFiles = listUploads();
    const r = await uploadMedia(srv.base, token, [{ field: "images", data: fixtures.jpegExif(9 * 1024 * 1024), type: "image/jpeg", name: "big.jpg" }]);
    assert.equal(r.status, 413);
    assert.deepEqual(r.json, { ok: false, error: "FILE_TOO_LARGE" });
    assert.deepEqual(listUploads(), beforeFiles);
  });

  test("more than 3 gallery images / unknown field -> 400 JSON", async () => {
    const four = Array.from({ length: 4 }, (_, i) => ({ field: "images", data: fixtures.png1x1(), type: "image/png", name: `${i}.png` }));
    const r1 = await uploadMedia(srv.base, token, four);
    assert.equal(r1.status, 400);
    assert.deepEqual(r1.json, { ok: false, error: "TOO_MANY_FILES" });
    const r2 = await uploadMedia(srv.base, token, [{ field: "avatar", data: fixtures.png1x1(), type: "image/png", name: "a.png" }]);
    assert.equal(r2.status, 400);
    assert.equal(r2.json.ok, false);
  });

  test("upload without / with a bad token -> 401", async () => {
    const r1 = await uploadMedia(srv.base, null, [{ field: "logo", data: fixtures.png1x1(), type: "image/png", name: "l.png" }]);
    assert.equal(r1.status, 401);
    const r2 = await uploadMedia(srv.base, "nope", [{ field: "logo", data: fixtures.png1x1(), type: "image/png", name: "l.png" }]);
    assert.equal(r2.status, 401);
  });

  test("uploaded URL uses PUBLIC_BASE_URL even with forged X-Forwarded-Host", async () => {
    const r = await uploadMedia(srv.base, token, [{ field: "logo", data: fixtures.png1x1(), type: "image/png", name: "l.png" }], {
      "X-Forwarded-Host": "attacker.example",
      "X-Forwarded-Proto": "http",
    });
    assert.equal(r.status, 200);
    assert.ok(r.json.logoUrl.startsWith(`${PUBLIC_URL}/uploads/`), r.json.logoUrl);
  });

  test("existing HTML/SVG/extension-less files on disk are only offered as downloads", async () => {
    for (const name of Object.keys(legacyFiles)) {
      const got = await request(srv.base, { path: `/uploads/${name}` });
      assert.equal(got.status, 200, name);
      assert.equal(got.headers["content-type"], "application/octet-stream", name);
      assert.equal(got.headers["content-disposition"], "attachment", name);
      assert.match(got.headers["content-security-policy"], /sandbox/, name);
      assert.equal(got.headers["x-content-type-options"], "nosniff", name);
    }
  });

  test("existing photo with a lying .png name still displays as an image (old uploads keep working)", async () => {
    const got = await request(srv.base, { path: "/uploads/legacy_photo.png" });
    assert.equal(got.status, 200);
    assert.equal(got.headers["content-type"], "image/png");
  });

  test("path traversal out of the uploads folder is impossible", async () => {
    for (const p of ["/uploads/..%2foutside-secret.txt", "/uploads/../outside-secret.txt", "/uploads/%2e%2e/outside-secret.txt", "/uploads/..%5coutside-secret.txt"]) {
      const got = await request(srv.base, { path: p });
      assert.notEqual(got.status, 200, p);
      assert.doesNotMatch(got.text, /TOP SECRET/, p);
    }
  });
});

// ---------------------------------------------------------------------------
describe("3. Rate limits can't be dodged with forged headers", () => {
  test("TRUST_PROXY_HOPS=1: forged left-most X-Forwarded-For is ignored; other clients unaffected", async () => {
    const srv = await startServer({ env: { TRUST_PROXY_HOPS: "1" } });
    try {
      const hit = (spoof, real, i) =>
        api(srv.base, "POST", "/api/auth/login-user", {
          json: { email: `nobody${i}@example.test`, password: "x" }, // different accounts: only the IP limit applies
          headers: { "X-Forwarded-For": `${spoof}, ${real}` },
        });
      for (let i = 0; i < 20; i++) assert.equal((await hit(`10.0.0.${i}`, "203.0.113.7", i)).status, 401);
      assert.equal((await hit("10.9.9.9", "203.0.113.7", 99)).status, 429, "same real client must be limited");
      assert.equal((await hit("10.0.0.1", "203.0.113.8", 100)).status, 401, "another real client must not be blocked");
    } finally {
      await srv.stop();
    }
  });
});

// ---------------------------------------------------------------------------
describe("4. Errors are JSON with proper status codes, no internals", () => {
  let srv;
  before(async () => {
    srv = await startServer({ env: { WEB_ORIGIN: "https://web.autohelp.test" } });
  });
  after(async () => srv.stop());

  const noLeak = (r) => assert.doesNotMatch(r.text, STACK_LEAK, r.text);

  test("disallowed origin -> 403 JSON (request and preflight)", async () => {
    const r = await request(srv.base, { path: "/api/companies", headers: { Origin: "https://evil.example" } });
    assert.equal(r.status, 403);
    assert.deepEqual(r.json, { ok: false, error: "CORS_NOT_ALLOWED" });
    noLeak(r);
    const pre = await request(srv.base, {
      method: "OPTIONS",
      path: "/api/auth/login-user",
      headers: { Origin: "https://evil.example", "Access-Control-Request-Method": "POST" },
    });
    assert.equal(pre.status, 403);
    assert.equal(pre.headers["access-control-allow-origin"], undefined);
  });

  test("app origins (Android/iOS WebView, web app, no Origin) are still allowed", async () => {
    for (const origin of ["capacitor://localhost", "ionic://localhost", "http://localhost", "https://localhost", "https://web.autohelp.test"]) {
      const pre = await request(srv.base, {
        method: "OPTIONS",
        path: "/api/auth/login-user",
        headers: { Origin: origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,authorization" },
      });
      assert.equal(pre.status, 204, origin);
      assert.equal(pre.headers["access-control-allow-origin"], origin, origin);
      const get = await request(srv.base, { path: "/api/companies", headers: { Origin: origin } });
      assert.equal(get.status, 200, origin);
    }
    assert.equal((await request(srv.base, { path: "/api/companies" })).status, 200);
  });

  test("broken JSON -> 400 INVALID_JSON", async () => {
    const r = await request(srv.base, { method: "POST", path: "/api/auth/login-user", headers: { "Content-Type": "application/json" }, body: "{bad json" });
    assert.equal(r.status, 400);
    assert.deepEqual(r.json, { ok: false, error: "INVALID_JSON" });
    noLeak(r);
  });

  test("oversized JSON body -> 413 PAYLOAD_TOO_LARGE", async () => {
    const r = await api(srv.base, "POST", "/api/auth/login-user", { json: { email: "x@y.z", password: "a".repeat(200 * 1024) } });
    assert.equal(r.status, 413);
    assert.deepEqual(r.json, { ok: false, error: "PAYLOAD_TOO_LARGE" });
  });

  test("unknown /api route -> 404 JSON", async () => {
    const r = await request(srv.base, { path: "/api/does-not-exist" });
    assert.equal(r.status, 404);
    assert.deepEqual(r.json, { ok: false, error: "NOT_FOUND" });
  });

  test("malformed upload request (not multipart) is handled without a crash", async () => {
    const { token } = await registerCompany(srv.base, "m@example.test");
    const r = await request(srv.base, {
      method: "POST",
      path: "/api/company/upload-media",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "multipart/form-data; boundary=xyz" },
      body: "--xyz\r\nbroken",
    });
    assert.ok([400, 413].includes(r.status), String(r.status));
    assert.equal(r.json?.ok, false);
    noLeak(r);
    assert.equal((await request(srv.base, { path: "/api/health" })).status, 200, "server still alive");
  });
});

// ---------------------------------------------------------------------------
describe("5. Real image files from the project (Android/web assets)", () => {
  const dirs = [path.join(SERVER_DIR, "..", "autohelp-web", "public", "images", "agw"), path.join(SERVER_DIR, "..", "autohelp-web", "icons")];
  const files = dirs.filter((d) => fs.existsSync(d)).flatMap((d) => fs.readdirSync(d).map((n) => path.join(d, n)));

  test("every real image is accepted and stored under its true type", { skip: files.length === 0 && "no sample images found" }, async () => {
    const srv = await startServer({ env: { PUBLIC_BASE_URL: PUBLIC_URL } });
    try {
      const { token } = await registerCompany(srv.base, "real@example.test");
      for (const f of files) {
        const data = fs.readFileSync(f);
        const r = await uploadMedia(srv.base, token, [{ field: "logo", data, type: "image/*", name: path.basename(f) }]);
        assert.equal(r.status, 200, `${f}: ${r.text}`);
        const trueExt = data[0] === 0xff ? ".jpg" : data[0] === 0x89 ? ".png" : data.toString("latin1", 8, 12) === "WEBP" ? ".webp" : "?";
        assert.ok(r.json.logoUrl.endsWith(trueExt), `${path.basename(f)} -> ${r.json.logoUrl}`);
      }
    } finally {
      await srv.stop();
    }
  });
});
