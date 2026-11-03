// Stage 1 follow-up: abuse vs. legitimate users.
// Progressive login throttling, time windows (fake clock), parallel requests,
// unknown accounts, the separate IP / e-mail limits, missing SMTP, disk faults.
// Tests marked "KNOWN LIMITATION" pin down current behaviour that is a
// deliberate trade-off or still needs a decision — they are not bugs fixed.
"use strict";

const { describe, test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");

const { startServer, startFakeSmtp, smtpEnv, api, uploadMedia, fixtures, waitFor, sleep } = require("./helpers");

const MIN = 60 * 1000;

const ipHeader = (ip) => (ip ? { "X-Forwarded-For": ip } : {});
const loginUser = (srv, email, password, ip) =>
  api(srv.base, "POST", "/api/auth/login-user", { json: { email, password }, headers: ipHeader(ip) });
const registerUser = (srv, email, password = "rightpass1", ip) =>
  api(srv.base, "POST", "/api/auth/register-user", {
    json: { firstName: "T", lastName: "U", username: email.split("@")[0], email, password },
    headers: ipHeader(ip),
  });
const retryAfter = (r) => Number(r.headers["retry-after"]);

async function withServer(opts, fn) {
  const srv = await startServer(opts);
  try {
    return await fn(srv);
  } finally {
    await srv.stop();
  }
}

// ---------------------------------------------------------------------------
describe("A. Progressive login throttling", () => {
  test("5 free failures, then waits of 1, 2, 4, 8, 16, 32, 64, 120, 120 s (Retry-After), same 429 body as before", () =>
    withServer({ fakeClock: true }, async (srv) => {
      assert.equal((await registerUser(srv, "seq@example.test")).status, 200);
      let n = 0;
      const ip = () => `198.51.100.${n++}`; // spread over IPs so only the account throttle is measured
      for (let i = 0; i < 5; i++) assert.equal((await loginUser(srv, "seq@example.test", "wrong", ip())).status, 401);
      const waits = [];
      for (let i = 0; i < 9; i++) {
        const blocked = await loginUser(srv, "seq@example.test", "wrong", ip());
        assert.equal(blocked.status, 429);
        assert.deepEqual(blocked.json, { ok: false, error: "RATE_LIMIT" }); // unchanged contract for old apps
        waits.push(retryAfter(blocked));
        await srv.advance(retryAfter(blocked) * 1000);
        assert.equal((await loginUser(srv, "seq@example.test", "wrong", ip())).status, 401);
      }
      assert.deepEqual(waits, [1, 2, 4, 8, 16, 32, 64, 120, 120]);
    }));

  test("while throttled even the correct password is not checked (no free guesses)", () =>
    withServer({ fakeClock: true }, async (srv) => {
      await registerUser(srv, "nocheck@example.test");
      for (let i = 0; i < 5; i++) await loginUser(srv, "nocheck@example.test", "wrong", `198.51.100.${i}`);
      const r = await loginUser(srv, "nocheck@example.test", "rightpass1", "198.51.100.77");
      assert.equal(r.status, 429);
      await srv.advance(retryAfter(r) * 1000);
      assert.equal((await loginUser(srv, "nocheck@example.test", "rightpass1", "198.51.100.77")).status, 200);
    }));

  test("time window: after 1 hour without failures the counter is forgotten", () =>
    withServer({ fakeClock: true }, async (srv) => {
      await registerUser(srv, "decay@example.test");
      for (let i = 0; i < 5; i++) await loginUser(srv, "decay@example.test", "wrong", "198.51.100.9");
      assert.equal((await loginUser(srv, "decay@example.test", "wrong", "198.51.100.9")).status, 429);
      await srv.advance(59 * MIN);
      assert.equal((await loginUser(srv, "decay@example.test", "wrong", "198.51.100.9")).status, 401, "1 s wait long over");
      assert.equal((await loginUser(srv, "decay@example.test", "wrong", "198.51.100.9")).status, 429, "still counted within the hour");
      await srv.advance(61 * MIN);
      for (let i = 0; i < 5; i++) {
        assert.equal((await loginUser(srv, "decay@example.test", "wrong", "198.51.100.9")).status, 401, `free attempt ${i + 1} again`);
      }
    }));

  test("brute force stays bounded: at most ~40 password checks per hour per account (same as the old lock)", () =>
    withServer({ fakeClock: true }, async (srv) => {
      await registerUser(srv, "brute@example.test");
      let checks = 0;
      let elapsed = 0;
      let i = 0;
      while (elapsed < 60 * MIN) {
        const r = await loginUser(srv, "brute@example.test", `guess${i++}`, `192.0.2.${i % 250}`); // forged, rotating IPs
        if (r.status === 401) checks++;
        else {
          assert.equal(r.status, 429);
          const ms = retryAfter(r) * 1000;
          await srv.advance(ms);
          elapsed += ms;
        }
      }
      assert.ok(checks <= 45, `checks per hour: ${checks}`);
      assert.ok(checks >= 35, `checks per hour: ${checks}`);
    }));

  test("no permanent lock-out: once the attack stops, the owner gets in after at most 120 s", () =>
    withServer({ fakeClock: true }, async (srv) => {
      await registerUser(srv, "owner@example.test");
      for (let i = 0; i < 30; i++) await loginUser(srv, "owner@example.test", "wrong", `192.0.2.${i}`); // burst, then stop
      const r = await loginUser(srv, "owner@example.test", "rightpass1", "203.0.113.10");
      assert.equal(r.status, 429);
      assert.ok(retryAfter(r) <= 120, `Retry-After ${retryAfter(r)}`);
      await srv.advance(120 * 1000);
      assert.equal((await loginUser(srv, "owner@example.test", "rightpass1", "203.0.113.10")).status, 200);
    }));

  test("KNOWN LIMITATION: during an ONGOING attack the owner is delayed too (up to 120 s per attempt)", () =>
    withServer({ fakeClock: true }, async (srv) => {
      await registerUser(srv, "busyowner@example.test");
      for (let i = 0; i < 12; i++) {
        const r = await loginUser(srv, "busyowner@example.test", "wrong", `192.0.2.${i}`);
        if (r.status === 429) await srv.advance(retryAfter(r) * 1000);
      }
      // the attacker keeps sending one failure every time the wait is over
      await loginUser(srv, "busyowner@example.test", "wrong", "192.0.2.200");
      const owner = await loginUser(srv, "busyowner@example.test", "rightpass1", "203.0.113.11");
      assert.equal(owner.status, 429);
      assert.ok(retryAfter(owner) <= 120);
    }));

  test("an address that logged in successfully before gets no privilege (IP is not trusted)", () =>
    withServer({ fakeClock: true }, async (srv) => {
      await registerUser(srv, "noip@example.test");
      assert.equal((await loginUser(srv, "noip@example.test", "rightpass1", "203.0.113.20")).status, 200);
      for (let i = 0; i < 5; i++) await loginUser(srv, "noip@example.test", "wrong", `192.0.2.${i}`);
      assert.equal((await loginUser(srv, "noip@example.test", "rightpass1", "203.0.113.20")).status, 429, "same counter for every address");
    }));

  test("legitimate typos: 4 wrong + correct, repeatedly, never throttles the owner", () =>
    withServer({ fakeClock: true }, async (srv) => {
      await registerUser(srv, "typo@example.test");
      await loginUser(srv, "typo@example.test", "rightpass1", "203.0.113.30");
      for (let round = 0; round < 3; round++) {
        for (let i = 0; i < 4; i++) assert.equal((await loginUser(srv, "typo@example.test", "wrong", "203.0.113.30")).status, 401);
        assert.equal((await loginUser(srv, "typo@example.test", "rightpass1", "203.0.113.30")).status, 200);
      }
    }));

  test("e-mail and username of the same account share one counter", () =>
    withServer({}, async (srv) => {
      await registerUser(srv, "both@example.test");
      for (let i = 0; i < 5; i++) await loginUser(srv, "both@example.test", "wrong", `192.0.2.${i}`);
      const byName = await api(srv.base, "POST", "/api/auth/login-user", { json: { username: "both", password: "wrong" }, headers: ipHeader("192.0.2.50") });
      assert.equal(byName.status, 429);
    }));

  test("company login: e-mail and company name share one counter; it expires", () =>
    withServer({ fakeClock: true }, async (srv) => {
      const reg = await api(srv.base, "POST", "/api/auth/register-company", {
        json: { companyName: "Kfz Muster", phone: "+43 660 1234567", address: "A 1, 1010 Wien", email: "kfz@example.test", password: "rightpass1", categories: ["repair"] },
      });
      assert.equal(reg.status, 200);
      const loginCo = (email, password, ip) => api(srv.base, "POST", "/api/auth/login-company", { json: { email, password }, headers: ipHeader(ip) });
      for (let i = 0; i < 5; i++) assert.equal((await loginCo("Kfz Muster", "wrong", `192.0.2.${i}`)).status, 401);
      const blocked = await loginCo("kfz@example.test", "rightpass1", "192.0.2.60");
      assert.equal(blocked.status, 429, "name and e-mail share the counter");
      await srv.advance(retryAfter(blocked) * 1000);
      assert.equal((await loginCo("kfz@example.test", "rightpass1", "203.0.113.40")).status, 200);
    }));
});

// ---------------------------------------------------------------------------
describe("B. Parallel requests", () => {
  test("30 simultaneous wrong logins: exactly 5 are checked, 25 are throttled", () =>
    withServer({}, async (srv) => {
      await registerUser(srv, "par@example.test");
      const results = await Promise.all(
        Array.from({ length: 30 }, (_, i) => loginUser(srv, "par@example.test", `p${i}`, `192.0.2.${i}`))
      );
      const counts = results.reduce((m, r) => ((m[r.status] = (m[r.status] || 0) + 1), m), {});
      assert.deepEqual(counts, { 401: 5, 429: 25 });
    }));

  test("simultaneous registrations with one e-mail: exactly one account", () =>
    withServer({}, async (srv) => {
      const results = await Promise.all(Array.from({ length: 5 }, (_, i) => registerUser(srv, "race@example.test", "rightpass1", `192.0.2.${i}`)));
      const statuses = results.map((r) => r.status).sort();
      assert.deepEqual(statuses, [200, 409, 409, 409, 409]);
    }));

  test("simultaneous wrong password changes: exactly 5 are checked", () =>
    withServer({}, async (srv) => {
      const { json } = await registerUser(srv, "pc@example.test");
      const results = await Promise.all(
        Array.from({ length: 12 }, () => api(srv.base, "PUT", "/api/user/password", { token: json.token, json: { currentPassword: "wrong", newPassword: "newpass123" } }))
      );
      const counts = results.reduce((m, r) => ((m[r.status] = (m[r.status] || 0) + 1), m), {});
      assert.deepEqual(counts, { 401: 5, 429: 7 });
      for (const r of results.filter((x) => x.status === 401)) assert.deepEqual(r.json, { ok: false, error: "WRONG_PASSWORD" });
    }));
});

// ---------------------------------------------------------------------------
describe("C. Login and password change have separate counters", () => {
  test("failed password changes don't block login; failed logins don't block password change", () =>
    withServer({}, async (srv) => {
      const { json } = await registerUser(srv, "sep@example.test");
      for (let i = 0; i < 8; i++) {
        await api(srv.base, "PUT", "/api/user/password", { token: json.token, json: { currentPassword: "wrong", newPassword: "newpass123" } });
      }
      assert.equal((await loginUser(srv, "sep@example.test", "rightpass1", "203.0.113.50")).status, 200, "login unaffected");
      for (let i = 0; i < 8; i++) await loginUser(srv, "sep@example.test", "wrong", `192.0.2.${i}`);
      const blockedChange = await api(srv.base, "PUT", "/api/user/password", { token: json.token, json: { currentPassword: "rightpass1", newPassword: "newpass123" } });
      assert.equal(blockedChange.status, 429, "still throttled by its OWN earlier failures");
    }));

  test("password change: only its own failures count; success clears them", () =>
    withServer({ fakeClock: true }, async (srv) => {
      const { json } = await registerUser(srv, "sep2@example.test");
      for (let i = 0; i < 8; i++) await loginUser(srv, "sep2@example.test", "wrong", `192.0.2.${i}`);
      const ok = await api(srv.base, "PUT", "/api/user/password", { token: json.token, json: { currentPassword: "rightpass1", newPassword: "newpass123" } });
      assert.equal(ok.status, 200, "login failures don't block the change");
      for (let i = 0; i < 4; i++) {
        await api(srv.base, "PUT", "/api/user/password", { token: json.token, json: { currentPassword: "wrong", newPassword: "x123456" } });
      }
      const ok2 = await api(srv.base, "PUT", "/api/user/password", { token: json.token, json: { currentPassword: "newpass123", newPassword: "third123" } });
      assert.equal(ok2.status, 200);
      for (let i = 0; i < 5; i++) {
        const r = await api(srv.base, "PUT", "/api/user/password", { token: json.token, json: { currentPassword: "wrong", newPassword: "x123456" } });
        assert.equal(r.status, 401, `fresh after success, attempt ${i + 1}`);
      }
    }));
});

// ---------------------------------------------------------------------------
describe("D. Unknown accounts look the same as existing ones", () => {
  test("same status and body: unknown e-mail / username / company vs. wrong password", () =>
    withServer({}, async (srv) => {
      await registerUser(srv, "real@example.test");
      await api(srv.base, "POST", "/api/auth/register-company", {
        json: { companyName: "Real Co", phone: "+43 660 1234567", address: "A 1, 1010 Wien", email: "co@example.test", password: "rightpass1", categories: ["repair"] },
      });
      const pairs = [
        [loginUser(srv, "real@example.test", "wrong", "192.0.2.1"), loginUser(srv, "ghost@example.test", "wrong", "192.0.2.2")],
        [
          api(srv.base, "POST", "/api/auth/login-user", { json: { username: "real", password: "wrong" }, headers: ipHeader("192.0.2.3") }),
          api(srv.base, "POST", "/api/auth/login-user", { json: { username: "ghost", password: "wrong" }, headers: ipHeader("192.0.2.4") }),
        ],
        [
          api(srv.base, "POST", "/api/auth/login-company", { json: { email: "co@example.test", password: "wrong" } }),
          api(srv.base, "POST", "/api/auth/login-company", { json: { email: "ghostco@example.test", password: "wrong" } }),
        ],
        [
          api(srv.base, "POST", "/api/auth/login-company", { json: { email: "Real Co", password: "wrong" } }),
          api(srv.base, "POST", "/api/auth/login-company", { json: { email: "Ghost Co", password: "wrong" } }),
        ],
      ];
      for (const [a, b] of pairs) {
        const [ra, rb] = await Promise.all([a, b]);
        assert.equal(ra.status, 401);
        assert.deepEqual([rb.status, rb.json], [ra.status, ra.json]);
      }
    }));

  test("unknown accounts are throttled exactly like existing ones (no hint via 429)", () =>
    withServer({}, async (srv) => {
      await registerUser(srv, "exists@example.test");
      const seq = async (email) => {
        const out = [];
        for (let i = 0; i < 7; i++) out.push((await loginUser(srv, email, "wrong", `192.0.2.${i}`)).status);
        return out;
      };
      assert.deepEqual(await seq("ghost2@example.test"), await seq("exists@example.test"));
    }));

  test("response time: unknown account is not noticeably faster than a wrong password", () =>
    withServer({}, async (srv) => {
      for (let i = 0; i < 7; i++) await registerUser(srv, `t${i}@example.test`, "rightpass1", `198.51.100.${i}`);
      const time = async (email, ip) => {
        const t0 = process.hrtime.bigint();
        await loginUser(srv, email, "wrong", ip);
        return Number(process.hrtime.bigint() - t0) / 1e6;
      };
      const known = [];
      const unknown = [];
      for (let i = 0; i < 7; i++) {
        known.push(await time(`t${i}@example.test`, `192.0.2.${i}`));
        unknown.push(await time(`nobody${i}@example.test`, `192.0.2.${100 + i}`));
      }
      const median = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
      const ratio = median(unknown) / median(known);
      assert.ok(ratio > 0.6 && ratio < 1.6, `median unknown ${median(unknown).toFixed(1)} ms vs known ${median(known).toFixed(1)} ms`);
    }));

  test("forgot-password answers immediately even when the mail server is slow (existing vs. unknown look alike)", async () => {
    const smtp = await startFakeSmtp({ greetingDelayMs: 1500 });
    try {
      await withServer({ env: { ...smtpEnv(smtp), PUBLIC_BASE_URL: "https://api.autohelp.test" } }, async (srv) => {
        await registerUser(srv, "slow@example.test");
        const t = async (email) => {
          const t0 = Date.now();
          const r = await api(srv.base, "POST", "/api/auth/forgot-password", { json: { email } });
          return { ms: Date.now() - t0, body: JSON.stringify([r.status, r.json]) };
        };
        const known = await t("slow@example.test");
        const unknown = await t("nobody@example.test");
        assert.equal(known.body, unknown.body);
        assert.ok(known.ms < 500, `existing account answered after ${known.ms} ms`);
        assert.ok(await waitFor(() => smtp.mails.length === 1, { timeoutMs: 8000 }), "mail still delivered afterwards");
      });
    } finally {
      await smtp.close();
    }
  });
});

// ---------------------------------------------------------------------------
describe("E. The separate IP limits (current values, not changed)", () => {
  // TRUST_PROXY_HOPS=1 so the test controls the client IP reliably.
  const env = { TRUST_PROXY_HOPS: "1" };
  const via = (ip) => ({ "X-Forwarded-For": `1.1.1.1, ${ip}` });

  test("registration: 10 per IP per 15 min; other IPs unaffected; window expires", () =>
    withServer({ env, fakeClock: true }, async (srv) => {
      const reg = (i, ip) =>
        api(srv.base, "POST", "/api/auth/register-user", { json: { firstName: "a", lastName: "b", username: `r${i}`, email: `r${i}@example.test`, password: "rightpass1" }, headers: via(ip) });
      for (let i = 0; i < 10; i++) assert.equal((await reg(i, "203.0.113.1")).status, 200);
      const blocked = await reg(10, "203.0.113.1");
      assert.equal(blocked.status, 429);
      assert.deepEqual(blocked.json, { ok: false, error: "RATE_LIMIT" });
      assert.equal((await reg(11, "203.0.113.2")).status, 200);
      await srv.advance(15 * MIN + 1000);
      assert.equal((await reg(12, "203.0.113.1")).status, 200);
    }));

  test("forgot-password: 5 per IP per 15 min; window expires", () =>
    withServer({ env, fakeClock: true }, async (srv) => {
      const f = (ip) => api(srv.base, "POST", "/api/auth/forgot-password", { json: { email: "x@example.test" }, headers: via(ip) });
      for (let i = 0; i < 5; i++) assert.equal((await f("203.0.113.3")).status, 200);
      assert.equal((await f("203.0.113.3")).status, 429);
      assert.equal((await f("203.0.113.4")).status, 200);
      await srv.advance(15 * MIN + 1000);
      assert.equal((await f("203.0.113.3")).status, 200);
    }));

  test("reset-password (token submit): 10 per IP per 15 min", () =>
    withServer({ env }, async (srv) => {
      const r = (ip) => api(srv.base, "POST", "/api/auth/reset-password", { json: { token: "abc", newPassword: "whatever1" }, headers: via(ip) });
      for (let i = 0; i < 10; i++) assert.equal((await r("203.0.113.5")).status, 400);
      assert.equal((await r("203.0.113.5")).status, 429);
      assert.equal((await r("203.0.113.6")).status, 400);
    }));

  test("KNOWN LIMITATION: login counts successful logins too — 20 per IP per 15 min (shared mobile/office IPs)", () =>
    withServer({ env }, async (srv) => {
      await registerUser(srv, "busy@example.test", "rightpass1");
      const login = (ip) => api(srv.base, "POST", "/api/auth/login-user", { json: { email: "busy@example.test", password: "rightpass1" }, headers: via(ip) });
      for (let i = 0; i < 20; i++) assert.equal((await login("203.0.113.7")).status, 200);
      assert.equal((await login("203.0.113.7")).status, 429, "21st successful login from one IP is refused today");
    }));
});

// ---------------------------------------------------------------------------
describe("F. Reset e-mails per address (current values, not changed)", () => {
  test("legitimate user: gets the mail, can ask again, quota returns after an hour", async () => {
    const smtp = await startFakeSmtp();
    try {
      await withServer({ env: smtpEnv(smtp), fakeClock: true }, async (srv) => {
        await registerUser(srv, "legit@example.test");
        const ask = () => api(srv.base, "POST", "/api/auth/forgot-password", { json: { email: "legit@example.test" }, headers: ipHeader("203.0.113.8") });
        await ask();
        await ask();
        assert.ok(await waitFor(() => smtp.mails.length === 2));
        await ask();
        await ask(); // 4th within the hour: same answer, no mail
        await waitFor(() => smtp.mails.length >= 3);
        await sleep(300);
        assert.equal(smtp.mails.length, 3);
        await srv.advance(61 * MIN);
        await ask();
        assert.ok(await waitFor(() => smtp.mails.length === 4), "quota is back after an hour");
      });
    } finally {
      await smtp.close();
    }
  });

  test("KNOWN LIMITATION: someone else can use up the 3 mails, the owner then gets none for up to an hour", async () => {
    const smtp = await startFakeSmtp();
    try {
      await withServer({ env: smtpEnv(smtp) }, async (srv) => {
        await registerUser(srv, "target@example.test");
        for (let i = 0; i < 10; i++) {
          await api(srv.base, "POST", "/api/auth/forgot-password", { json: { email: "target@example.test" }, headers: ipHeader(`192.0.2.${i}`) });
        }
        await waitFor(() => smtp.mails.length >= 3);
        const owner = await api(srv.base, "POST", "/api/auth/forgot-password", { json: { email: "target@example.test" }, headers: ipHeader("203.0.113.9") });
        assert.equal(owner.status, 200);
        await sleep(300);
        assert.equal(smtp.mails.length, 3, "inbox flooding is capped at 3 ... but the owner's request sends nothing");
      });
    } finally {
      await smtp.close();
    }
  });
});

// ---------------------------------------------------------------------------
describe("G. Missing SMTP configuration", () => {
  test("forgot-password still answers the same for existing and unknown accounts; nothing breaks", () =>
    withServer({ env: { SMTP_HOST: undefined } }, async (srv) => {
      await registerUser(srv, "nosmtp@example.test");
      const a = await api(srv.base, "POST", "/api/auth/forgot-password", { json: { email: "nosmtp@example.test", lang: "bg" } });
      const b = await api(srv.base, "POST", "/api/auth/forgot-password", { json: { email: "nobody@example.test", lang: "bg" } });
      assert.equal(a.status, 200);
      assert.deepEqual([b.status, b.json], [a.status, a.json]);
      const health = await api(srv.base, "GET", "/health");
      assert.equal(health.json.hasSmtp, false);
    }));
});

// ---------------------------------------------------------------------------
describe("H. Disk faults during upload", () => {
  const co = (srv) =>
    api(srv.base, "POST", "/api/auth/register-company", {
      json: { companyName: "Disk Co", phone: "+43 660 1234567", address: "A 1, 1010 Wien", email: "disk@example.test", password: "rightpass1", categories: ["repair"] },
    });

  test("2nd file fails to write (disk full): 500 UPLOAD_FAILED, the 1st file is removed, profile unchanged", () =>
    withServer({ fsFault: "write2" }, async (srv) => {
      const { json } = await co(srv);
      const r = await uploadMedia(srv.base, json.token, [
        { field: "logo", data: fixtures.png1x1(), type: "image/png", name: "l.png" },
        { field: "images", data: fixtures.jpegExif(), type: "image/jpeg", name: "a.jpg" },
      ]);
      assert.equal(r.status, 500);
      assert.deepEqual(r.json, { ok: false, error: "UPLOAD_FAILED" });
      assert.deepEqual(fs.readdirSync(srv.uploads), [], "no partial files left");
      const company = await api(srv.base, "GET", `/api/companies/${json.company.id}`);
      assert.equal(company.json.item.logoUrl, null);
      assert.deepEqual(company.json.item.images, []);
      assert.equal((await api(srv.base, "GET", "/api/health")).status, 200);
    }));

  test("upload folder not writable: 500 UPLOADS_NOT_AVAILABLE (unchanged contract), nothing written", () =>
    withServer({ fsFault: "access" }, async (srv) => {
      const { json } = await co(srv);
      const r = await uploadMedia(srv.base, json.token, [{ field: "logo", data: fixtures.png1x1(), type: "image/png", name: "l.png" }]);
      assert.equal(r.status, 500);
      assert.deepEqual(r.json, { ok: false, error: "UPLOADS_NOT_AVAILABLE" });
      assert.deepEqual(fs.readdirSync(srv.uploads), []);
    }));
});

