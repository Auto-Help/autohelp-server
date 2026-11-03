// API compatibility for installed apps (Android 1.1.4 / iOS 1.0.6).
//
// Runs the same request sequence an old app makes against the committed
// server (git HEAD) and against the working copy, each on its own empty
// temp database, and requires identical answers (status codes + JSON bodies,
// with random ids/tokens/timestamps normalised) — except for the steps in
// INTENDED below, where the new answer must be exactly the listed fix.
"use strict";

const { test, after } = require("node:test");
const assert = require("node:assert/strict");

const { startServer, startFakeSmtp, smtpEnv, request, api, uploadMedia, fixtures, headIndexCopy, waitFor, sleep } = require("./helpers");

const PUBLIC_URL = "https://api.autohelp.test";

function normalize(value, key = "") {
  if (Array.isArray(value)) return value.map((v) => normalize(v));
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = normalize(value[k], k);
    return out;
  }
  if (typeof value === "string") {
    if (/^ey[\w-]+\.[\w-]+\.[\w-]+$/.test(value)) return "<jwt>";
    if (/^[ucr]_[0-9a-f]{20}$/.test(value)) return `<${value[0]}-id>`;
    // Extension case may differ on purpose: HEAD took it from the client's file
    // name (IMG_1.JPG), the new server from the content (.jpg). Same image either way.
    if (/\/uploads\//.test(value)) return value.replace(/\/uploads\/[^/]+?(\.[a-z]+)$/i, (_, ext) => `/uploads/<file>${ext.toLowerCase()}`);
    if (["time", "created_at", "updated_at"].includes(key)) return "<time>";
  }
  if (typeof value === "number" && ["createdAt"].includes(key)) return "<ts>";
  // Open/closed depends on the moment of the run (and HEAD used the machine's
  // time zone); it is tested with a fixed clock in stage2. Unknown (null) still compared.
  if (typeof value === "boolean" && key === "openNow") return "<bool>";
  return value;
}

const clone = (x) => JSON.parse(JSON.stringify(x));
const entry = (log, step) => log.find((e) => e.step === step);

// Fixed baseline: the server the installed apps were built against
// (225613a). Comparing with the moving git HEAD broke once later stages were
// committed (HEAD then already "has" every intended change).
const BASELINE = "225613a";

// Digital Garage: vehicle answers gain new keys (empty for these vehicles);
// every key an installed app knows keeps its value.
const GARAGE_KEYS = { plate: null, current_km: null, current_km_at: null, timing_drive: null, odometer_reminder: 0, client_ref: null };
const withGarageKeys = (v) => Object.assign(v, GARAGE_KEYS);

// Deliberate changes (Stage 2), as an old app sees them. Each maps HEAD's
// answer to the exact answer the new server must give.
const INTENDED = {
  // Stage 3: a malformed e-mail address is refused at registration
  "register-user-bad-email": (e) => ({ ...e, status: 400, body: { error: "INVALID_EMAIL", ok: false } }),
  // servicesText typed in the registration form is now kept
  "register-company": (e) => ((e.body.company.servicesText = "Öl, Bremsen"), e),
  "login-company-name": (e) => ((e.body.company.servicesText = "Öl, Bremsen"), e),
  "login-company": (e) => ((e.body.company.servicesText = "Öl, Bremsen"), e),
  // saving the dashboard with empty coordinate fields no longer wipes the position ...
  "company-by-id-after-empty-coords": (e) => ((e.body.item.lat = 48.2082), (e.body.item.lng = 16.3738), e),
  // ... so the company stays in the 5 km search
  "radius-after-empty-coords": (e, log) => ({ ...e, body: clone(entry(log, "companies-radius").body) }),
  // ratings for a company that doesn't exist are refused
  "rate-unknown-company": (e) => ({ ...e, status: 404, body: { error: "NOT_FOUND", ok: false } }),
  // the token of a deleted account no longer works
  "me-after-delete": (e) => ({ ...e, status: 401, body: { error: "INVALID_TOKEN", ok: false } }),
  "rate-after-delete": (e) => ({ ...e, status: 401, body: { error: "INVALID_TOKEN", ok: false } }),
  "upload-after-delete-company": (e) => ({ ...e, status: 401, body: { error: "INVALID_TOKEN", ok: false } }),
  "profile-after-delete-company": (e) => ({ ...e, status: 401, body: { error: "INVALID_TOKEN", ok: false } }),
  // Digital Garage: new vehicle keys
  "vehicles": (e) => (e.body.vehicles.forEach(withGarageKeys), e),
  "vehicle-put-pickerl": (e) => (withGarageKeys(e.body.vehicle), e),
  "vehicle-put-legacy": (e) => (withGarageKeys(e.body.vehicle), e),
  "vehicle-post": (e) => (withGarageKeys(e.body.vehicle), e),
  "vehicles-after": (e) => (e.body.vehicles.forEach(withGarageKeys), e),
};

async function oldAppScenario(base, smtp) {
  const log = [];
  const rec = async (step, p) => {
    const r = await p;
    log.push({ step, status: r.status, body: normalize(r.json ?? r.text) });
    return r;
  };
  const cap = { Origin: "capacitor://localhost" };

  await rec("health", api(base, "GET", "/api/health"));
  await rec("preflight", request(base, { method: "OPTIONS", path: "/api/auth/login-user", headers: { ...cap, "Access-Control-Request-Method": "POST" } }).then((r) => ({ status: r.status, json: { acao: r.headers["access-control-allow-origin"], acac: r.headers["access-control-allow-credentials"] } })));

  // --- user registration / login (Register.jsx, Login.jsx) ---
  const reg = await rec("register-user", api(base, "POST", "/api/auth/register-user", {
    headers: cap,
    json: { firstName: "Ana", lastName: "B", username: "ana", email: "Ana@Example.test", password: "secret123", lang: "bg", car_make: "VW", car_model: "Golf", car_reg_month: 3, car_reg_year: 2015, car_pickerl_month: 5, car_pickerl_year: 2027 },
  }));
  await rec("register-user-dup", api(base, "POST", "/api/auth/register-user", { json: { firstName: "A", lastName: "B", username: "x", email: "ana@example.test", password: "secret123" } }));
  await rec("register-user-bad-email", api(base, "POST", "/api/auth/register-user", { json: { firstName: "A", lastName: "B", username: "bad", email: "Bad Name <bad@example.test>", password: "secret123" } }));
  await rec("register-user-invalid",api(base, "POST", "/api/auth/register-user", { json: { email: "q@example.test", password: "1" } }));
  await rec("login-email", api(base, "POST", "/api/auth/login-user", { json: { email: "ana@example.test", username: "", password: "secret123" } }));
  await rec("login-username", api(base, "POST", "/api/auth/login-user", { json: { email: "", username: "ana", password: "secret123" } }));
  await rec("login-wrong", api(base, "POST", "/api/auth/login-user", { json: { email: "ana@example.test", password: "nope" } }));
  await rec("login-missing", api(base, "POST", "/api/auth/login-user", { json: {} }));
  const userToken = reg.json.token;

  // --- company (CompanyRegister.jsx, CompanyLogin.jsx, CompanyDashboard.jsx) ---
  await rec("register-company-badphone", api(base, "POST", "/api/auth/register-company", {
    json: { companyName: "Shop", phone: "0660 123", address: "A 1, 1010 Wien, AT", email: "shop@example.test", password: "secret123", categories: ["service"] },
  }));
  const creg = await rec("register-company", api(base, "POST", "/api/auth/register-company", {
    json: { companyName: "Shop", phone: "+43 660 1234567", address: "A 1, 1010 Wien, AT", email: "shop@example.test", password: "secret123", categories: ["service", "inspection"], lang: "de", servicesText: "Öl, Bremsen", openingHours: { mon: { enabled: true, open: "09:00", close: "18:00" } } },
  }));
  const companyId = creg.json.company.id;
  await rec("login-company-name", api(base, "POST", "/api/auth/login-company", { json: { email: "Shop", password: "secret123" } }));
  const clog = await rec("login-company", api(base, "POST", "/api/auth/login-company", { json: { email: "shop@example.test", password: "secret123" } }));
  await rec("login-company-wrong", api(base, "POST", "/api/auth/login-company", { json: { email: "shop@example.test", password: "x" } }));
  const ctoken = clog.json.token;

  await rec("upload", uploadMedia(base, ctoken, [
    { field: "logo", data: fixtures.png1x1(), type: "image/png", name: "logo.png" },
    { field: "images", data: fixtures.jpegExif(), type: "image/jpeg", name: "a.jpg" },
    { field: "images", data: fixtures.jpegExif(), type: "image/jpeg", name: "b.jpg" },
  ], cap));
  await rec("upload-48mp-photo", uploadMedia(base, ctoken, [{ field: "images", data: fixtures.jpeg(8064, 6048, 6 * 1024 * 1024), type: "image/jpeg", name: "IMG_4821.JPG" }], cap));
  await rec("upload-heic-iphone", uploadMedia(base, ctoken, [{ field: "logo", data: fixtures.heicIphone(4032, 3024), type: "image/heic", name: "IMG_4822.heic" }], cap));
  await rec("upload-noauth", uploadMedia(base, null, [{ field: "logo", data: fixtures.png1x1(), type: "image/png", name: "l.png" }]));
  const workingHoursJson = JSON.stringify({ sun: [], mon: [["08:00", "17:00"]], tue: [["08:00", "17:00"]], wed: [], thu: [], fri: [], sat: [] });
  await rec("update-profile", api(base, "POST", "/api/company/update-profile", {
    token: ctoken,
    json: { lat: 48.2082, lng: 16.3738, workingHoursJson, servicesText: "Öl\nBremsen", logoUrl: `${PUBLIC_URL}/uploads/x.png`, imagesJson: "[]", companyName: "Shop GmbH", phone: "+43 660 1234567", address: "A 1, 1010 Wien, AT", email: "shop@example.test" },
  }));
  await rec("update-profile-badphone", api(base, "POST", "/api/company/update-profile", { token: ctoken, json: { phone: "12" } }));
  await rec("company-by-id", api(base, "GET", `/api/companies/${companyId}`));
  await rec("companies-list", api(base, "GET", "/api/companies?category=service&limit=50"));
  await rec("companies-radius", api(base, "GET", "/api/companies?category=inspection&limit=50&lat=48.21&lng=16.37&radiusKm=5"));
  await rec("companies-far", api(base, "GET", "/api/companies?category=inspection&limit=50&lat=47.07&lng=15.44&radiusKm=5"));
  await rec("nearby", api(base, "GET", "/api/companies/nearby?lat=48.21&lng=16.37"));
  await rec("nearest", api(base, "GET", "/api/companies/nearest?lat=48.21&lng=16.37"));
  await rec("view", api(base, "POST", `/api/companies/${companyId}/view`));
  await rec("call", api(base, "POST", `/api/companies/${companyId}/call`));
  // Dashboard save after its data failed to load: coordinate fields empty.
  await rec("update-profile-empty-coords", api(base, "POST", "/api/company/update-profile", {
    token: ctoken,
    json: { lat: null, lng: null, workingHoursJson, servicesText: "Öl\nBremsen", logoUrl: `${PUBLIC_URL}/uploads/x.png`, imagesJson: "[]", companyName: "Shop GmbH", phone: "+43 660 1234567", address: "A 1, 1010 Wien, AT", email: "shop@example.test" },
  }));
  await rec("company-by-id-after-empty-coords", api(base, "GET", `/api/companies/${companyId}`));
  await rec("radius-after-empty-coords", api(base, "GET", "/api/companies?category=inspection&limit=50&lat=48.21&lng=16.37&radiusKm=5"));

  // --- ratings (ServiceDetail.jsx) ---
  await rec("rate", api(base, "POST", "/api/ratings", { token: userToken, json: { serviceId: companyId, value: 4 } }));
  await rec("rate-again", api(base, "POST", "/api/ratings", { token: userToken, json: { serviceId: companyId, value: 5 } }));
  await rec("rate-noauth", api(base, "POST", "/api/ratings", { json: { serviceId: companyId, value: 5 } }));
  await rec("rate-unknown-company", api(base, "POST", "/api/ratings", { token: userToken, json: { serviceId: "c_00000000000000000000", value: 5 } }));
  await rec("rating-stats", api(base, "GET", `/api/ratings/stats/${companyId}`));

  // --- settings / vehicles / Pickerl (UserSettings.jsx) ---
  await rec("me", api(base, "GET", "/api/user/me", { token: userToken }));
  const vs = await rec("vehicles", api(base, "GET", "/api/user/vehicles", { token: userToken }));
  const vid = vs.json.vehicles[0].id;
  await rec("vehicle-put-pickerl", api(base, "PUT", `/api/user/vehicles/${vid}`, { token: userToken, json: { make: "VW", model: "Golf", reg_month: 3, reg_year: 2015, pickerl_month: 6, pickerl_year: 2028 } }));
  await rec("vehicle-put-legacy", api(base, "PUT", `/api/user/vehicles/${vid}`, { token: userToken, json: { make: "VW", model: "Polo", reg_month: 3, reg_year: 2015 } }));
  await rec("vehicle-put-badpickerl", api(base, "PUT", `/api/user/vehicles/${vid}`, { token: userToken, json: { pickerl_month: 13, pickerl_year: 2028 } }));
  await rec("vehicle-post", api(base, "POST", "/api/user/vehicles", { token: userToken, json: { make: "Audi", pickerl_month: null, pickerl_year: null } }));
  await rec("vehicles-after", api(base, "GET", "/api/user/vehicles", { token: userToken }));
  await rec("password-wrong", api(base, "PUT", "/api/user/password", { token: userToken, json: { currentPassword: "nope", newPassword: "newpass123" } }));
  await rec("password-ok", api(base, "PUT", "/api/user/password", { token: userToken, json: { currentPassword: "secret123", newPassword: "newpass123" } }));
  await rec("me-email", api(base, "PUT", "/api/user/me", { token: userToken, json: { email: "ana2@example.test" } }));
  await rec("bad-token", api(base, "GET", "/api/user/me", { token: "garbage" }));
  await rec("company-token-on-user-route", api(base, "GET", "/api/user/vehicles", { token: ctoken }));

  // --- forgot / reset (ForgotPassword.jsx, ResetPassword.jsx) ---
  await rec("forgot-unknown", api(base, "POST", "/api/auth/forgot-password", { json: { email: "zzz@example.test", lang: "bg" } }));
  const mailsBefore = smtp.mails.length;
  await rec("forgot-known", api(base, "POST", "/api/auth/forgot-password", { json: { email: "ana2@example.test", lang: "en" } }));
  await waitFor(() => smtp.mails.length > mailsBefore);
  await sleep(200);
  log.push({ step: "forgot-mail-sent", value: smtp.mails.length - mailsBefore });
  await rec("reset-bad-token", api(base, "POST", "/api/auth/reset-password", { json: { token: "abc", newPassword: "whatever1" } }));
  await rec("reset-short", api(base, "POST", "/api/auth/reset-password", { json: { token: "abc", newPassword: "1" } }));
  const landing = await request(base, { path: "/reset-password?token=abc123" });
  log.push({ step: "reset-landing", status: landing.status, hasDeepLink: landing.text.includes("autohelp:///reset-password?token=abc123") });

  // --- account deletion (AccountDelete.jsx) ---
  await rec("delete-user", api(base, "DELETE", "/api/auth/delete-user", { token: userToken }));
  await rec("me-after-delete", api(base, "GET", "/api/user/me", { token: userToken }));
  await rec("rate-after-delete", api(base, "POST", "/api/ratings", { token: userToken, json: { serviceId: companyId, value: 1 } }));
  await rec("delete-company", api(base, "DELETE", "/api/auth/delete-company", { token: ctoken }));
  await rec("upload-after-delete-company", uploadMedia(base, ctoken, [{ field: "logo", data: fixtures.png1x1(), type: "image/png", name: "l.png" }]));
  await rec("profile-after-delete-company", api(base, "POST", "/api/company/update-profile", { token: ctoken, json: { companyName: "Ghost" } }));
  return log;
}

let head;
after(() => head?.cleanup());

test("old-app API sequence gives identical answers on HEAD and on the working copy", async () => {
  head = headIndexCopy(BASELINE);
  const smtp = await startFakeSmtp();
  const env = { ...smtpEnv(smtp), PUBLIC_BASE_URL: PUBLIC_URL, WEB_ORIGIN: "https://web.autohelp.test" };
  try {
    const oldSrv = await startServer({ env, script: head.file });
    let oldLog;
    try {
      oldLog = await oldAppScenario(oldSrv.base, smtp);
    } finally {
      await oldSrv.stop();
    }
    const newSrv = await startServer({ env });
    let newLog;
    try {
      newLog = await oldAppScenario(newSrv.base, smtp);
    } finally {
      await newSrv.stop();
    }
    assert.equal(newLog.length, oldLog.length);
    for (let i = 0; i < oldLog.length; i++) {
      const step = oldLog[i].step;
      const fix = INTENDED[step];
      const expected = fix ? fix(clone(oldLog[i]), newLog) : oldLog[i];
      if (fix) assert.notDeepEqual(expected, oldLog[i], `step ${step}: listed as a change, but HEAD already behaves like this`);
      assert.deepEqual(newLog[i], expected, `step ${step}`);
    }
    for (const step of Object.keys(INTENDED)) assert.ok(entry(oldLog, step), `intended step ${step} was not exercised`);
  } finally {
    await smtp.close();
  }
});
