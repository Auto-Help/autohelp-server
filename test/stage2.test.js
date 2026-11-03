// Stage 2: company data and ratings.
//   1. coordinates are never wiped by a profile save
//   2. servicesText from the registration form is stored
//   3. no fictitious 09:00–18:00 hours for new companies
//   4. tokens of deleted accounts are refused (401)
//   5. open/closed in Europe/Vienna: summer/winter time, overnight, 24/7
//   6. own rating: read and change; old POST (409 on a second vote) unchanged
"use strict";

const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");

const { startServer, api, uploadMedia, fixtures } = require("./helpers");

let ipSeq = 0;
const freshIp = () => ({ "X-Forwarded-For": `198.18.${Math.floor(ipSeq / 250)}.${ipSeq++ % 250}` }); // stay under the per-IP registration limit

async function registerCompany(srv, extra = {}) {
  const n = ipSeq;
  const r = await api(srv.base, "POST", "/api/auth/register-company", {
    headers: freshIp(),
    json: { companyName: `Co ${n}`, phone: "+43 660 1234567", address: "Ring 1, 1010 Wien, AT", email: `co${n}@example.test`, password: "rightpass1", categories: ["repair"], ...extra },
  });
  assert.equal(r.status, 200, r.text);
  return r.json;
}

async function registerUser(srv) {
  const n = ipSeq;
  const r = await api(srv.base, "POST", "/api/auth/register-user", {
    headers: freshIp(),
    json: { firstName: "T", lastName: "U", username: `u${n}`, email: `u${n}@example.test`, password: "rightpass1" },
  });
  assert.equal(r.status, 200, r.text);
  return r.json;
}

const getCompany = async (srv, id) => (await api(srv.base, "GET", `/api/companies/${id}`)).json.item;
const save = (srv, token, json) => api(srv.base, "POST", "/api/company/update-profile", { token, json });

// The exact payload builder of the installed dashboard (CompanyDashboard.jsx).
function dashboardHoursJson(openingHours) {
  const out = {};
  for (const k of ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]) {
    const day = openingHours?.[k];
    if (day && day.enabled && day.open && day.close) out[k] = [[String(day.open), String(day.close)]];
    else out[k] = [];
  }
  return JSON.stringify(out);
}
const DASHBOARD_DEFAULTS = {
  mon: { enabled: true, open: "09:00", close: "18:00" },
  tue: { enabled: true, open: "09:00", close: "18:00" },
  wed: { enabled: true, open: "09:00", close: "18:00" },
  thu: { enabled: true, open: "09:00", close: "18:00" },
  fri: { enabled: true, open: "09:00", close: "18:00" },
  sat: { enabled: false, open: "09:00", close: "13:00" },
  sun: { enabled: false, open: "09:00", close: "13:00" },
};

// ---------------------------------------------------------------------------
describe("1. Coordinates are never wiped by a profile save", () => {
  let srv;
  let co;
  const VIENNA = { lat: 48.2082, lng: 16.3738 };

  before(async () => {
    srv = await startServer();
    co = await registerCompany(srv, VIENNA);
  });
  after(async () => srv.stop());

  // The installed dashboard always sends every field, coordinates included.
  const dashboardSave = (lat, lng) =>
    save(srv, co.token, {
      lat,
      lng,
      workingHoursJson: dashboardHoursJson(DASHBOARD_DEFAULTS),
      servicesText: "x",
      logoUrl: "",
      imagesJson: "[]",
      companyName: co.company.companyName,
      phone: co.company.phone,
      address: co.company.address,
      email: co.company.email,
    });

  for (const [label, lat, lng] of [
    ["empty fields (null, null) — dashboard data failed to load", null, null],
    ["empty strings", "", ""],
    ["only latitude", 47.07, null],
    ["text", "abc", "def"],
    ["out of range", 200, 16.37],
    ["0, 0 (no position)", 0, 0],
    ["missing keys", undefined, undefined],
  ]) {
    test(`keeps the stored position: ${label}`, async () => {
      const r = await dashboardSave(lat, lng);
      assert.equal(r.status, 200);
      assert.deepEqual(r.json, { ok: true });
      const c = await getCompany(srv, co.company.id);
      assert.deepEqual([c.lat, c.lng], [VIENNA.lat, VIENNA.lng]);
      const near = await api(srv.base, "GET", `/api/companies?category=repair&limit=50&lat=48.21&lng=16.37&radiusKm=5`);
      assert.ok(near.json.items.some((i) => i.id === co.company.id), "still found within 5 km");
    });
  }

  test("a valid new pair is stored (also with a decimal comma)", async () => {
    assert.equal((await dashboardSave(47.0707, 15.4395)).status, 200);
    let c = await getCompany(srv, co.company.id);
    assert.deepEqual([c.lat, c.lng], [47.0707, 15.4395]);
    assert.equal((await dashboardSave("48,2082", "16,3738")).status, 200);
    c = await getCompany(srv, co.company.id);
    assert.deepEqual([c.lat, c.lng], [48.2082, 16.3738]);
  });

  test("a save with nothing to change still answers ok (as before)", async () => {
    const r = await save(srv, co.token, { lat: null, lng: null });
    assert.deepEqual([r.status, r.json], [200, { ok: true }]);
  });

  test("registration with invalid coordinates stores no position (instead of a broken one)", async () => {
    const bad = await registerCompany(srv, { lat: 95, lng: 16.3 });
    assert.deepEqual([bad.company.lat, bad.company.lng], [null, null]);
    const c = await getCompany(srv, bad.company.id);
    assert.deepEqual([c.lat, c.lng], [null, null]);
  });
});

// ---------------------------------------------------------------------------
describe("2. servicesText from the registration form is stored", () => {
  let srv;
  before(async () => {
    srv = await startServer();
  });
  after(async () => srv.stop());

  test("old registration form payload: text kept (trimmed) and returned everywhere", async () => {
    const co = await registerCompany(srv, {
      servicesText: "  Ölwechsel\nBremsen, Reifen  ",
      lang: "de",
      openingHours: DASHBOARD_DEFAULTS, // what the installed form sends along
    });
    assert.equal(co.company.servicesText, "Ölwechsel\nBremsen, Reifen");
    assert.equal((await getCompany(srv, co.company.id)).servicesText, "Ölwechsel\nBremsen, Reifen");
    const login = await api(srv.base, "POST", "/api/auth/login-company", { json: { email: co.company.email, password: "rightpass1" } });
    assert.equal(login.json.company.servicesText, "Ölwechsel\nBremsen, Reifen");
    const list = await api(srv.base, "GET", "/api/companies?category=repair&limit=50");
    assert.equal(list.json.items.find((i) => i.id === co.company.id).servicesText, "Ölwechsel\nBremsen, Reifen");
  });

  test("missing or non-text servicesText -> empty string, as before", async () => {
    assert.equal((await registerCompany(srv)).company.servicesText, "");
    assert.equal((await registerCompany(srv, { servicesText: 42 })).company.servicesText, "");
  });

  test("the dashboard can still change it later", async () => {
    const co = await registerCompany(srv, { servicesText: "A" });
    assert.equal((await save(srv, co.token, { servicesText: "B" })).status, 200);
    assert.equal((await getCompany(srv, co.company.id)).servicesText, "B");
  });
});

// ---------------------------------------------------------------------------
describe("3. No fictitious hours for new companies", () => {
  let srv;
  before(async () => {
    srv = await startServer();
  });
  after(async () => srv.stop());

  test("old registration form (sends 09:00–18:00 defaults as openingHours): hours stay unknown", async () => {
    const co = await registerCompany(srv, { openingHours: DASHBOARD_DEFAULTS });
    const c = await getCompany(srv, co.company.id);
    assert.equal(c.workingHoursJson, null);
    assert.equal(c.openNow, null, "unknown, not open/closed");
    const list = await api(srv.base, "GET", "/api/companies?category=repair&limit=50");
    assert.equal(list.json.items.find((i) => i.id === co.company.id).openNow, null);
  });

  test("hours the company really sends at registration are stored", async () => {
    const hours = JSON.stringify({ mon: [["07:00", "16:00"]], sun: [] });
    const co = await registerCompany(srv, { workingHoursJson: hours });
    assert.equal((await getCompany(srv, co.company.id)).workingHoursJson, hours);
  });

  test("existing hours are untouched by saves that don't send hours", async () => {
    const co = await registerCompany(srv);
    const hours = dashboardHoursJson({ ...DASHBOARD_DEFAULTS, sat: { enabled: true, open: "08:00", close: "12:00" } });
    assert.equal((await save(srv, co.token, { workingHoursJson: hours })).status, 200);
    assert.equal((await save(srv, co.token, { servicesText: "x", lat: null, lng: null })).status, 200);
    assert.equal((await getCompany(srv, co.company.id)).workingHoursJson, hours);
  });

  test("every shape the installed dashboard produces is accepted", async () => {
    const co = await registerCompany(srv);
    const variants = [
      DASHBOARD_DEFAULTS,
      {},
      { mon: { enabled: true, open: "", close: "" } },
      { mon: { enabled: false, open: "09:00", close: "18:00" } },
      { fri: { enabled: true, open: "22:00", close: "06:00" } },
      { mon: { enabled: true, open: "00:00", close: "23:59" } },
      { mon: { enabled: true, open: "08:00:00", close: "17:30:00" } },
    ];
    for (const v of variants) {
      const r = await save(srv, co.token, { workingHoursJson: dashboardHoursJson(v) });
      assert.equal(r.status, 200, JSON.stringify(v));
    }
  });

  test("garbage hours are refused (400 INVALID_WORKING_HOURS) and nothing is changed", async () => {
    const co = await registerCompany(srv, { servicesText: "before" });
    for (const bad of ["not json", "[1,2]", '{"mon":"09-18"}', '{"mon":[["9","18"]]}', '{"mon":[["25:00","26:00"]]}', '{"xyz":[]}', '{"mon":[["24:00","06:00"]]}']) {
      const r = await save(srv, co.token, { workingHoursJson: bad, servicesText: "after" });
      assert.deepEqual([r.status, r.json], [400, { ok: false, error: "INVALID_WORKING_HOURS" }], bad);
    }
    const c = await getCompany(srv, co.company.id);
    assert.equal(c.servicesText, "before");
    assert.equal(c.workingHoursJson, null);
  });
});

// ---------------------------------------------------------------------------
describe("4. Tokens of deleted accounts are refused", () => {
  let srv;
  before(async () => {
    srv = await startServer({ env: { JWT_SECRET: "stage2-test-secret" } });
  });
  after(async () => srv.stop());

  const invalid = { ok: false, error: "INVALID_TOKEN" };

  test("deleted user: every user route answers 401 INVALID_TOKEN", async () => {
    const u = await registerUser(srv);
    const co = await registerCompany(srv);
    assert.equal((await api(srv.base, "GET", "/api/user/me", { token: u.token })).status, 200);
    assert.equal((await api(srv.base, "DELETE", "/api/auth/delete-user", { token: u.token })).status, 200);
    for (const [method, p, json] of [
      ["GET", "/api/user/me"],
      ["GET", "/api/user/vehicles"],
      ["POST", "/api/user/vehicles", { make: "VW" }],
      ["PUT", "/api/user/password", { currentPassword: "rightpass1", newPassword: "x123456" }],
      ["POST", "/api/ratings", { serviceId: co.company.id, value: 5 }],
      ["PUT", `/api/ratings/${co.company.id}`, { value: 5 }],
      ["GET", `/api/ratings/mine/${co.company.id}`],
      ["DELETE", "/api/auth/delete-user"],
    ]) {
      const r = await api(srv.base, method, p, { token: u.token, json });
      assert.deepEqual([r.status, r.json], [401, invalid], `${method} ${p}`);
    }
    assert.equal((await api(srv.base, "GET", `/api/ratings/stats/${co.company.id}`)).json.votes, 0, "no orphan rating created");
  });

  test("deleted company: profile, upload and delete answer 401, no files written", async () => {
    const co = await registerCompany(srv);
    assert.equal((await api(srv.base, "DELETE", "/api/auth/delete-company", { token: co.token })).status, 200);
    assert.deepEqual((await save(srv, co.token, { companyName: "Ghost" })).json, invalid);
    const up = await uploadMedia(srv.base, co.token, [{ field: "logo", data: fixtures.png1x1(), type: "image/png", name: "l.png" }]);
    assert.deepEqual([up.status, up.json], [401, invalid]);
    assert.deepEqual(require("node:fs").readdirSync(srv.uploads), []);
    assert.equal((await api(srv.base, "DELETE", "/api/auth/delete-company", { token: co.token })).status, 401);
  });

  test("a correctly signed token for an id that never existed is refused", async () => {
    const forgedUser = jwt.sign({ type: "user", userId: "u_does_not_exist" }, "stage2-test-secret");
    const forgedCo = jwt.sign({ type: "company", companyId: "c_does_not_exist" }, "stage2-test-secret");
    assert.equal((await api(srv.base, "GET", "/api/user/me", { token: forgedUser })).status, 401);
    assert.equal((await save(srv, forgedCo, { companyName: "x" })).status, 401);
  });

  test("not activated: after a password change the old token still works (planned for later)", async () => {
    const u = await registerUser(srv);
    const r = await api(srv.base, "PUT", "/api/user/password", { token: u.token, json: { currentPassword: "rightpass1", newPassword: "newpass123" } });
    assert.equal(r.status, 200);
    assert.equal((await api(srv.base, "GET", "/api/user/me", { token: u.token })).status, 200);
  });

  test("existing accounts are unaffected (user and company)", async () => {
    const u = await registerUser(srv);
    const co = await registerCompany(srv);
    assert.equal((await api(srv.base, "GET", "/api/user/vehicles", { token: u.token })).status, 200);
    assert.equal((await save(srv, co.token, { servicesText: "ok" })).status, 200);
  });
});

// ---------------------------------------------------------------------------
describe("5. Open / closed in Europe/Vienna", () => {
  let srv;
  before(async () => {
    // Render runs on UTC; the result must not depend on the server's time zone.
    srv = await startServer({ fakeClock: true, env: { TZ: "UTC" } });
  });
  after(async () => srv.stop());

  const weekdays918 = { sun: [], mon: [["09:00", "18:00"]], tue: [["09:00", "18:00"]], wed: [["09:00", "18:00"]], thu: [["09:00", "18:00"]], fri: [["09:00", "18:00"]], sat: [] };
  const allDays = (slot) => Object.fromEntries(["sun", "mon", "tue", "wed", "thu", "fri", "sat"].map((d) => [d, [slot]]));
  const U = (s) => Date.parse(s); // ISO with Z = UTC

  // [label, hours, UTC moment, expected openNow]
  const cases = [
    // Winter time (CET = UTC+1). The old code used the server clock (UTC on Render).
    ["winter Wed 09:30 Vienna (08:30 UTC) is open", weekdays918, "2026-01-14T08:30:00Z", true],
    ["winter Wed 08:30 Vienna is closed", weekdays918, "2026-01-14T07:30:00Z", false],
    ["winter Wed 17:59 Vienna is open", weekdays918, "2026-01-14T16:59:00Z", true],
    ["winter Wed 18:00 Vienna is closed (end not included)", weekdays918, "2026-01-14T17:00:00Z", false],
    // Summer time (CEST = UTC+2).
    ["summer Wed 08:30 Vienna (06:30 UTC) is closed", weekdays918, "2026-07-15T06:30:00Z", false],
    ["summer Wed 09:00 Vienna is open", weekdays918, "2026-07-15T07:00:00Z", true],
    ["summer Wed 18:30 Vienna (16:30 UTC) is closed", weekdays918, "2026-07-15T16:30:00Z", false],
    ["Saturday closed", weekdays918, "2026-07-18T10:00:00Z", false],
    // Change to summer time, Sun 29.03.2026: 02:00 CET -> 03:00 CEST.
    ["DST start: 01:30 CET, slot 03:00–04:00 not yet open", { sun: [["03:00", "04:00"]] }, "2026-03-29T00:30:00Z", false],
    ["DST start: 03:30 CEST, slot 03:00–04:00 open", { sun: [["03:00", "04:00"]] }, "2026-03-29T01:30:00Z", true],
    // Change to winter time, Sun 25.10.2026: 03:00 CEST -> 02:00 CET (02:xx happens twice).
    ["DST end: first 02:30 (CEST)", { sun: [["02:00", "03:00"]] }, "2026-10-25T00:30:00Z", true],
    ["DST end: second 02:30 (CET)", { sun: [["02:00", "03:00"]] }, "2026-10-25T01:30:00Z", true],
    ["DST end: 03:30 CET is closed", { sun: [["02:00", "03:00"]] }, "2026-10-25T02:30:00Z", false],
    // Overnight Fri 22:00 – Sat 06:00.
    ["overnight: Fri 21:30 closed", { fri: [["22:00", "06:00"]], sat: [] }, "2026-01-16T20:30:00Z", false],
    ["overnight: Fri 22:30 open", { fri: [["22:00", "06:00"]], sat: [] }, "2026-01-16T21:30:00Z", true],
    ["overnight: Sat 05:00 open (from Friday)", { fri: [["22:00", "06:00"]], sat: [] }, "2026-01-17T04:00:00Z", true],
    ["overnight: Sat 06:30 closed", { fri: [["22:00", "06:00"]], sat: [] }, "2026-01-17T05:30:00Z", false],
    ["overnight across the week: Sun 22:00 – Mon 06:00, Mon 04:00 open", { sun: [["22:00", "06:00"]], mon: [] }, "2026-01-19T03:00:00Z", true],
    ["overnight in summer time: Sat 05:00 CEST open", { fri: [["22:00", "06:00"]], sat: [] }, "2026-07-18T03:00:00Z", true],
    ["overnight, next day not listed: Sat 05:00 open", { fri: [["22:00", "06:00"]] }, "2026-01-17T04:00:00Z", true],
    ["overnight, next day not listed: Sat 07:00 unknown", { fri: [["22:00", "06:00"]] }, "2026-01-17T06:00:00Z", null],
    // 24/7
    ["24/7 (00:00–24:00): Wed 23:59 open", allDays(["00:00", "24:00"]), "2026-01-14T22:59:30Z", true],
    ["24/7: Thu 00:00 open", allDays(["00:00", "24:00"]), "2026-01-14T23:00:00Z", true],
    ["24/7: summer Sun 03:00 open", allDays(["00:00", "24:00"]), "2026-07-19T01:00:00Z", true],
    ["24/7 written as 00:00–00:00: open", allDays(["00:00", "00:00"]), "2026-01-14T12:00:00Z", true],
    ["evening until midnight 18:00–24:00: 23:59 open", { wed: [["18:00", "24:00"]] }, "2026-01-14T22:59:00Z", true],
    // Unknown / closed
    ["no hours at all: unknown", null, "2026-01-14T10:00:00Z", null],
    ["day not listed: unknown", { mon: [["09:00", "18:00"]] }, "2026-01-14T10:00:00Z", null],
    ["two slots (lunch break): 12:30 closed", { wed: [["08:00", "12:00"], ["13:00", "17:00"]] }, "2026-01-14T11:30:00Z", false],
    ["two slots (lunch break): 13:30 open", { wed: [["08:00", "12:00"], ["13:00", "17:00"]] }, "2026-01-14T12:30:00Z", true],
  ];

  test("all cases via GET /api/companies/:id", async () => {
    const ids = [];
    for (const [, hours] of cases) {
      const co = await registerCompany(srv, hours ? { workingHoursJson: JSON.stringify(hours) } : {});
      ids.push(co.company.id);
    }
    for (let i = 0; i < cases.length; i++) {
      const [label, , moment, expected] = cases[i];
      await srv.setNow(U(moment));
      const c = await getCompany(srv, ids[i]);
      assert.equal(c.openNow, expected, label);
    }
  });

  test("same answers whatever the server's own time zone (UTC+14 here)", async () => {
    const far = await startServer({ fakeClock: true, env: { TZ: "Pacific/Kiritimati" } });
    try {
      for (const i of [0, 3, 6, 9, 10, 15, 21]) {
        const [label, hours, moment, expected] = cases[i];
        const co = await registerCompany(far, { workingHoursJson: JSON.stringify(hours) });
        await far.setNow(U(moment));
        assert.equal((await getCompany(far, co.company.id)).openNow, expected, label);
      }
    } finally {
      await far.stop();
    }
  });

  test("the list and the nearby search use the same rule", async () => {
    const co = await registerCompany(srv, { lat: 48.2, lng: 16.37, workingHoursJson: JSON.stringify(weekdays918), categories: ["wash"] });
    await srv.setNow(U("2026-07-15T07:30:00Z")); // 09:30 summer time
    const list = await api(srv.base, "GET", "/api/companies?category=wash&limit=50");
    assert.equal(list.json.items.find((i) => i.id === co.company.id).openNow, true);
    const near = await api(srv.base, "GET", "/api/companies/nearby?lat=48.2&lng=16.37&category=wash");
    assert.equal(near.json.items.find((i) => i.id === co.company.id).openNow, true);
    await srv.setNow(U("2026-07-15T16:30:00Z")); // 18:30 summer time
    assert.equal((await api(srv.base, "GET", "/api/companies?category=wash&limit=50")).json.items.find((i) => i.id === co.company.id).openNow, false);
  });

  test("older stored format [{day, from, to}] is still read", async () => {
    const co = await registerCompany(srv);
    const db = new Database(path.join(srv.dir, "test.sqlite"));
    db.prepare("UPDATE companies SET workingHoursJson = ? WHERE id = ?").run(JSON.stringify([{ day: "wed", from: "09:00", to: "18:00" }]), co.company.id);
    db.close();
    await srv.setNow(U("2026-01-14T08:30:00Z"));
    assert.equal((await getCompany(srv, co.company.id)).openNow, true);
    await srv.setNow(U("2026-01-15T08:30:00Z")); // Thursday: not listed
    assert.equal((await getCompany(srv, co.company.id)).openNow, null);
  });
});

// ---------------------------------------------------------------------------
describe("6. Own rating: read and change", () => {
  let srv;
  let user;
  let co;
  before(async () => {
    srv = await startServer();
    user = await registerUser(srv);
    co = await registerCompany(srv);
  });
  after(async () => srv.stop());

  const mine = (token, id) => api(srv.base, "GET", `/api/ratings/mine/${id}`, { token });
  const put = (token, id, value) => api(srv.base, "PUT", `/api/ratings/${id}`, { token, json: { value } });

  test("full flow: none -> POST 201 -> POST again 409 (old apps) -> PUT changes it", async () => {
    let r = await mine(user.token, co.company.id);
    assert.deepEqual([r.status, r.json.rating], [200, null]);

    r = await api(srv.base, "POST", "/api/ratings", { token: user.token, json: { serviceId: co.company.id, value: 4 } });
    assert.equal(r.status, 201);
    assert.deepEqual(r.json.stats, { average: 4, votes: 1 });

    r = await api(srv.base, "POST", "/api/ratings", { token: user.token, json: { serviceId: co.company.id, value: 5 } });
    assert.deepEqual([r.status, r.json], [409, { ok: false, error: "ALREADY_VOTED" }]);

    r = await mine(user.token, co.company.id);
    assert.equal(r.json.rating.value, 4);
    const firstId = r.json.rating.id;

    r = await put(user.token, co.company.id, 2);
    assert.equal(r.status, 200);
    assert.equal(r.json.rating.value, 2);
    assert.equal(r.json.rating.id, firstId, "the same rating is changed, not a second one added");
    assert.deepEqual(r.json.stats, { average: 2, votes: 1 });

    const stats = await api(srv.base, "GET", `/api/ratings/stats/${co.company.id}`);
    assert.deepEqual([stats.json.average, stats.json.votes], [2, 1]);
  });

  test("PUT without an earlier rating creates it", async () => {
    const u2 = await registerUser(srv);
    const r = await put(u2.token, co.company.id, 5);
    assert.equal(r.status, 200);
    assert.equal(r.json.rating.value, 5);
    assert.equal(r.json.stats.votes, 2);
  });

  test("users only see their own rating", async () => {
    const u3 = await registerUser(srv);
    assert.equal((await mine(u3.token, co.company.id)).json.rating, null);
  });

  test("invalid values / unknown company / no or wrong token", async () => {
    for (const v of [0, 6, 3.5, "x", null]) {
      assert.deepEqual((await put(user.token, co.company.id, v)).json, { ok: false, error: "INVALID_INPUT" }, String(v));
    }
    assert.deepEqual([(await put(user.token, "c_00000000000000000000", 3)).status], [404]);
    const post = await api(srv.base, "POST", "/api/ratings", { token: user.token, json: { serviceId: "c_00000000000000000000", value: 3 } });
    assert.deepEqual([post.status, post.json], [404, { ok: false, error: "NOT_FOUND" }]);
    assert.equal((await put(null, co.company.id, 3)).status, 401);
    assert.equal((await put(co.token, co.company.id, 3)).status, 401, "company token can't rate");
    assert.equal((await mine(null, co.company.id)).status, 401);
    assert.equal((await mine(user.token, co.company.id)).json.rating.value, 2, "unchanged by the failed attempts");
  });

  test("parallel PUTs by one user: still exactly one rating", async () => {
    const u4 = await registerUser(srv);
    const co2 = await registerCompany(srv);
    const values = [1, 2, 3, 4, 5, 1, 2, 3, 4, 5];
    const results = await Promise.all(values.map((v) => put(u4.token, co2.company.id, v)));
    assert.ok(results.every((r) => r.status === 200));
    const stats = await api(srv.base, "GET", `/api/ratings/stats/${co2.company.id}`);
    assert.equal(stats.json.votes, 1);
    assert.ok(values.includes((await mine(u4.token, co2.company.id)).json.rating.value));
  });

  test("parallel POST + PUT by one user: one rating, POST either 201 or 409", async () => {
    const u5 = await registerUser(srv);
    const co3 = await registerCompany(srv);
    const [p, q] = await Promise.all([
      api(srv.base, "POST", "/api/ratings", { token: u5.token, json: { serviceId: co3.company.id, value: 3 } }),
      put(u5.token, co3.company.id, 4),
    ]);
    assert.ok([201, 409].includes(p.status));
    assert.equal(q.status, 200);
    assert.equal((await api(srv.base, "GET", `/api/ratings/stats/${co3.company.id}`)).json.votes, 1);
  });
});
