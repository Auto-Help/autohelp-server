// Stage 8 (final audit): small fixes found while re-reading the server.
// - a driver's e-mail change may not take an address a company already uses
//   (forgot-password would then reach the driver, never the company)
// - /health doesn't show server paths in production
// - an odd "lang" value in forgot-password can't pick built-in object properties
"use strict";

const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");

const { startServer, startFakeSmtp, smtpEnv, api, waitFor, extractResetLink } = require("./helpers");

let n = 0;
const ip = () => ({ "X-Forwarded-For": `198.20.${Math.floor(n / 250)}.${n++ % 250}` });

describe("Stage 8 fixes", () => {
  let srv;
  let smtp;
  before(async () => {
    smtp = await startFakeSmtp();
    srv = await startServer({ env: { ...smtpEnv(smtp), PUBLIC_BASE_URL: "https://api.autohelp.test" } });
  });
  after(async () => {
    await srv.stop();
    await smtp.close();
  });

  const registerUser = (email) =>
    api(srv.base, "POST", "/api/auth/register-user", { headers: ip(), json: { firstName: "A", lastName: "B", username: `s8u${n}`, email, password: "rightpass1" } });
  const registerCompany = (email) =>
    api(srv.base, "POST", "/api/auth/register-company", {
      headers: ip(),
      json: { companyName: `S8 Co ${n}`, phone: "+43 660 1234567", address: "A 1, 1010 Wien", email, password: "rightpass1", categories: ["repair"] },
    });

  test("driver e-mail change to a company's address: 409 EMAIL_EXISTS, nothing changed; company reset still reaches the company", async () => {
    const co = await registerCompany("werkstatt@example.at");
    assert.equal(co.status, 200);
    const u = await registerUser("fahrer@example.at");
    assert.equal(u.status, 200);

    const r = await api(srv.base, "PUT", "/api/user/me", { token: u.json.token, json: { email: "Werkstatt@Example.at" } });
    assert.deepEqual([r.status, r.json], [409, { ok: false, error: "EMAIL_EXISTS" }]);
    const me = await api(srv.base, "GET", "/api/user/me", { token: u.json.token });
    assert.equal(me.json.user.email, "fahrer@example.at");

    // the company can still reset its own password with that address
    const start = smtp.mails.length;
    await api(srv.base, "POST", "/api/auth/forgot-password", { headers: ip(), json: { email: "werkstatt@example.at", lang: "de" } });
    await waitFor(() => smtp.mails.length > start);
    const link = extractResetLink(smtp.mails[smtp.mails.length - 1]);
    const token = new URL(link).searchParams.get("token");
    const reset = await api(srv.base, "POST", "/api/auth/reset-password", { headers: ip(), json: { token, newPassword: "newpass123" } });
    assert.equal(reset.status, 200);
    const login = await api(srv.base, "POST", "/api/auth/login-company", { headers: ip(), json: { email: "werkstatt@example.at", password: "newpass123" } });
    assert.equal(login.status, 200);
  });

  test("driver e-mail change: other cases unchanged (own address, free address, another driver's address)", async () => {
    const a = await registerUser("erster@example.at");
    await registerUser("zweiter@example.at");
    const same = await api(srv.base, "PUT", "/api/user/me", { token: a.json.token, json: { email: "erster@example.at" } });
    assert.equal(same.status, 200);
    const taken = await api(srv.base, "PUT", "/api/user/me", { token: a.json.token, json: { email: "zweiter@example.at" } });
    assert.deepEqual([taken.status, taken.json], [409, { ok: false, error: "EMAIL_EXISTS" }]);
    const free = await api(srv.base, "PUT", "/api/user/me", { token: a.json.token, json: { email: "neu@example.at" } });
    assert.equal(free.status, 200);
  });

  test("/health in production: status fields kept, no server paths", async () => {
    const h = await api(srv.base, "GET", "/health");
    assert.equal(h.status, 200);
    assert.equal(h.json.ok, true);
    assert.equal(typeof h.json.hasSmtp, "boolean");
    assert.equal(typeof h.json.dbFileExists, "boolean");
    assert.equal(h.json.uploadDir, undefined);
    assert.equal(h.json.dbFile, undefined);
    assert.ok(!JSON.stringify(h.json).includes(srv.dir.replace(/\\/g, "\\\\")));
  });

  test("forgot-password with lang 'constructor' / '__proto__': normal generic answer and an English mail", async () => {
    await registerUser("sprache@example.at");
    const normal = await api(srv.base, "POST", "/api/auth/forgot-password", { headers: ip(), json: { email: "nobody@example.at", lang: "en" } });
    for (const lang of ["constructor", "__proto__", "toString"]) {
      const r = await api(srv.base, "POST", "/api/auth/forgot-password", { headers: ip(), json: { email: "nobody@example.at", lang } });
      assert.deepEqual([r.status, r.json], [normal.status, normal.json], lang);
    }
    const start = smtp.mails.length;
    await api(srv.base, "POST", "/api/auth/forgot-password", { headers: ip(), json: { email: "sprache@example.at", lang: "constructor" } });
    await waitFor(() => smtp.mails.length > start);
    const mail = smtp.mails[smtp.mails.length - 1];
    assert.match(mail, /Subject: .*Reset_your_password/);
    assert.match(mail, /click this link to reset your password/);
    assert.ok(extractResetLink(mail));
  });
});

describe("/health outside production keeps the diagnostics", () => {
  test("development: paths still shown (local troubleshooting)", async () => {
    const srv = await startServer({ env: { NODE_ENV: "development" } });
    try {
      const h = await api(srv.base, "GET", "/health");
      assert.equal(typeof h.json.dbFile, "string");
      assert.equal(typeof h.json.uploadDir, "string");
    } finally {
      await srv.stop();
    }
  });
});
