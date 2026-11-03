// Stage 3 (option B): e-mail address format checks instead of the nodemailer
// major upgrade. Registration, e-mail change and forgot-password.
"use strict";

const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const Database = require("better-sqlite3");

const { startServer, startFakeSmtp, smtpEnv, api, waitFor, sleep } = require("./helpers");

const VALID = [
  "anna.mueller@example.at",
  "Max.Muster@Example.AT", // stored lower-case
  "max+autohelp@gmail.com",
  "o'brien@example.co.uk",
  "first_last-1@sub.domain.example.com",
  "x@müller.at", // letters of any script in the domain
  "a@xn--mller-kva.at", // punycode
  "user@123.example.com",
  `${"a".repeat(64)}@example.com`, // longest local part
  `a@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(60)}`, // exactly 254 characters
];

const INVALID = [
  ["no @", "anna.example.at"],
  ["two @", "a@b@example.at"],
  ["space", "anna mueller@example.at"],
  ["list with a comma", "a@example.at,b@evil.example"],
  ["list with a semicolon", "a@example.at;b@evil.example"],
  ["display name", "Anna <anna@example.at>"],
  ["angle brackets", "<anna@example.at>"],
  ["quoted local part", '"a@evil"@example.at'],
  ["comment", "anna(comment)@example.at"],
  ["CRLF injection", "anna@example.at\r\nBcc: x@evil.example"],
  ["no domain dot", "anna@localhost"],
  ["IP literal", "anna@[127.0.0.1]"],
  ["numeric top-level domain", "anna@example.123"],
  ["label starting with -", "anna@-example.at"],
  ["empty label", "anna@example..at"],
  ["trailing dot", "anna@example.at."],
  ["leading dot in local part", ".anna@example.at"],
  ["double dot in local part", "an..na@example.at"],
  ["local part over 64", `${"a".repeat(65)}@example.com`],
  ["over 254 characters", `a@${"b".repeat(63)}.${"c".repeat(63)}.${"d".repeat(63)}.${"e".repeat(61)}`],
  ["parser stress (addressparser DoS shape)", `${"(".repeat(20000)}@example.at`],
  ["very long garbage", `${"<a@b>,".repeat(8000)}`],
];

let n = 0;
const ip = () => ({ "X-Forwarded-For": `198.19.${Math.floor(n / 250)}.${n++ % 250}` });

describe("E-mail format checks", () => {
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
    api(srv.base, "POST", "/api/auth/register-user", { headers: ip(), json: { firstName: "A", lastName: "B", username: `u${n}`, email, password: "rightpass1" } });
  const registerCompany = (email) =>
    api(srv.base, "POST", "/api/auth/register-company", {
      headers: ip(),
      json: { companyName: `Co ${n}`, phone: "+43 660 1234567", address: "A 1, 1010 Wien", email, password: "rightpass1", categories: ["repair"] },
    });

  for (const email of VALID) {
    test(`valid: ${email.length > 40 ? `${email.slice(0, 30)}… (${email.length})` : email}`, async () => {
      const r = await registerUser(email);
      assert.equal(r.status, 200, r.text);
      assert.equal(r.json.user.email, email.trim().toLowerCase());
    });
  }

  for (const [label, email] of INVALID) {
    test(`invalid (${label}): registration refused, nothing stored`, async () => {
      const t0 = Date.now();
      const u = await registerUser(email);
      assert.deepEqual([u.status, u.json], [400, { ok: false, error: "INVALID_EMAIL" }]);
      const c = await registerCompany(email);
      assert.deepEqual([c.status, c.json], [400, { ok: false, error: "INVALID_EMAIL" }]);
      assert.ok(Date.now() - t0 < 1500, "answered quickly");
    });
  }

  test("forgot-password: invalid address -> the same generic answer, no mail", async () => {
    const start = smtp.mails.length;
    const ok = await api(srv.base, "POST", "/api/auth/forgot-password", { headers: ip(), json: { email: "anna.mueller@example.at" } });
    for (const [, email] of INVALID.slice(0, 12)) {
      const r = await api(srv.base, "POST", "/api/auth/forgot-password", { headers: ip(), json: { email } });
      assert.deepEqual([r.status, r.json], [ok.status, ok.json], email);
    }
    await waitFor(() => smtp.mails.length - start >= 1);
    await sleep(300);
    assert.equal(smtp.mails.length - start, 1, "only the valid, existing address got a mail");
  });

  test("e-mail change (user): invalid refused, valid accepted, unchanged legacy address still allowed", async () => {
    const reg = await registerUser("change.me@example.at");
    const token = reg.json.token;
    const put = (email) => api(srv.base, "PUT", "/api/user/me", { token, json: { email } });
    assert.deepEqual((await put("a@b@c.at")).json, { ok: false, error: "INVALID_EMAIL" });
    assert.deepEqual((await put("new.address@example.at")).json, { ok: true });
    // An account created before the check, with a non-conforming address:
    const db = new Database(path.join(srv.dir, "test.sqlite"));
    db.prepare("UPDATE users SET email = ? WHERE id = ?").run("legacy@intranet", reg.json.user.id);
    db.close();
    assert.deepEqual((await put("legacy@intranet")).json, { ok: true }, "re-saving the stored address is not blocked");
  });

  test("legacy account with a non-conforming address can still log in; reset just sends nothing", async () => {
    const reg = await registerUser("legacy2@example.at");
    const db = new Database(path.join(srv.dir, "test.sqlite"));
    db.prepare("UPDATE users SET email = ? WHERE id = ?").run("legacy2@intranet", reg.json.user.id);
    db.close();
    const login = await api(srv.base, "POST", "/api/auth/login-user", { headers: ip(), json: { email: "legacy2@intranet", password: "rightpass1" } });
    assert.equal(login.status, 200);
    const start = smtp.mails.length;
    const r = await api(srv.base, "POST", "/api/auth/forgot-password", { headers: ip(), json: { email: "legacy2@intranet" } });
    assert.equal(r.status, 200);
    await sleep(300);
    assert.equal(smtp.mails.length, start);
  });

  test("company dashboard: changed invalid e-mail refused; unchanged legacy e-mail doesn't block other fields", async () => {
    const reg = await registerCompany("shop.dash@example.at");
    const token = reg.json.token;
    const save = (json) => api(srv.base, "POST", "/api/company/update-profile", { token, json });
    assert.deepEqual((await save({ email: "Shop <x@y.at>", servicesText: "a" })).json, { ok: false, error: "INVALID_EMAIL" });
    const db = new Database(path.join(srv.dir, "test.sqlite"));
    db.prepare("UPDATE companies SET email = ? WHERE id = ?").run("legacy@shop", reg.json.company.id);
    db.close();
    const r = await save({ email: "legacy@shop", servicesText: "still saves", phone: "+43 660 1234567" });
    assert.deepEqual(r.json, { ok: true });
    assert.equal((await api(srv.base, "GET", `/api/companies/${reg.json.company.id}`)).json.item.servicesText, "still saves");
  });
});
