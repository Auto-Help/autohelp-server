// Stage 9 — Digital Garage backend (Etap 1 of the Personal Dashboard work).
// - new vehicle fields (plate, odometer, timing drive, odometer reminder)
//   that installed app versions never wipe (absent key = keep)
// - service plans (driver's own intervals: km, months or both)
// - full service history (create / old entries / details / edit / delete)
// - odometer updates with a guarded decrease
// - up to 5 vehicles, resent requests never create duplicates
// - ownership: nobody reads or changes another user's garage
// - deleting a vehicle or the account removes its garage data
// - Pickerl data is never touched by any garage operation
// - an existing database migrates additively and still works on the old server
"use strict";

const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { startServer, api, headIndexCopy } = require("./helpers");

// The live server before Digital Garage (production since 2026-10-12).
const LIVE_BASELINE = "4fdec51";

let n = 0;
const ip = () => ({ "X-Forwarded-For": `198.31.${Math.floor(n / 250)}.${n++ % 250}` });

function viennaDate(offsetDays = 0) {
  const f = new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Vienna", year: "numeric", month: "2-digit", day: "2-digit" });
  const p = Object.fromEntries(f.formatToParts(new Date(Date.now() + offsetDays * 86400000)).map((x) => [x.type, x.value]));
  return `${p.year}-${p.month}-${p.day}`;
}

async function registerUser(base, tag, extra = {}) {
  const r = await api(base, "POST", "/api/auth/register-user", {
    headers: ip(),
    json: { firstName: "G", lastName: "T", username: `gar${tag}${n}`, email: `gar.${tag}.${n}@example.at`, password: "rightpass1", ...extra },
  });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  return { token: r.json.token, id: r.json.user.id, email: r.json.user.email };
}

const GARAGE_KEYS = ["plate", "current_km", "current_km_at", "timing_drive", "odometer_reminder", "client_ref"];

describe("Digital Garage backend", () => {
  let srv;
  let base;
  before(async () => {
    srv = await startServer();
    base = srv.base;
  });
  after(async () => srv?.stop());

  const call = (method, p, token, json) => api(base, method, p, { token, json });
  const newVehicle = async (token, json = {}) => {
    const r = await call("POST", "/api/user/vehicles", token, { make: "VW", model: "Golf", reg_month: 3, reg_year: 2015, ...json });
    assert.equal(r.status, 201, JSON.stringify(r.json));
    return r.json.vehicle;
  };

  // ---------- vehicle fields ----------
  test("a vehicle can be created with plate, odometer, timing drive and odometer reminder", async () => {
    const u = await registerUser(base, "a");
    const v = await newVehicle(u.token, { plate: "  w-12345 x ", current_km: 120000, timing_drive: "belt", odometer_reminder: true });
    assert.equal(v.plate, "W-12345 X");
    assert.equal(v.current_km, 120000);
    assert.ok(Number.isInteger(v.current_km_at));
    assert.equal(v.timing_drive, "belt");
    assert.equal(v.odometer_reminder, 1);

    const plain = await newVehicle(u.token);
    assert.equal(plain.plate, null);
    assert.equal(plain.current_km, null);
    assert.equal(plain.timing_drive, null);
    assert.equal(plain.odometer_reminder, 0, "odometer reminder is off by default");
  });

  test("vehicle garage fields are validated on the server", async () => {
    const u = await registerUser(base, "b");
    const bad = [
      [{ plate: "W<script>" }, "INVALID_PLATE"],
      [{ plate: "X".repeat(17) }, "INVALID_PLATE"],
      [{ plate: 123 }, "INVALID_PLATE"],
      [{ timing_drive: "rubber" }, "INVALID_TIMING_DRIVE"],
      [{ odometer_reminder: "yes" }, "INVALID_ODOMETER_REMINDER"],
      [{ current_km: -1 }, "INVALID_KM"],
      [{ current_km: 2000001 }, "INVALID_KM"],
      [{ current_km: "120.000" }, "INVALID_KM"],
      [{ current_km: 12.5 }, "INVALID_KM"],
      [{ client_ref: "short" }, "INVALID_CLIENT_REF"],
    ];
    for (const [json, code] of bad) {
      const r = await call("POST", "/api/user/vehicles", u.token, { make: "X", ...json });
      assert.deepEqual([r.status, r.json], [400, { ok: false, error: code }], JSON.stringify(json));
    }
    const list = await call("GET", "/api/user/vehicles", u.token);
    assert.equal(list.json.vehicles.length, 0, "nothing was created by invalid requests");
  });

  test("PUT without the new keys (installed app versions) keeps plate, timing drive, reminder, odometer and Pickerl", async () => {
    const u = await registerUser(base, "c");
    const v = await newVehicle(u.token, { plate: "W-1 AB", current_km: 90000, timing_drive: "chain", odometer_reminder: true, pickerl_month: 6, pickerl_year: 2028 });

    // exactly what the released UserSettings sends
    const r = await call("PUT", `/api/user/vehicles/${v.id}`, u.token, { make: "VW", model: "Polo", reg_month: 3, reg_year: 2015, pickerl_month: 6, pickerl_year: 2028 });
    assert.equal(r.status, 200);
    assert.equal(r.json.vehicle.model, "Polo");
    for (const k of ["plate", "current_km", "current_km_at", "timing_drive", "odometer_reminder"]) assert.deepEqual(r.json.vehicle[k], v[k], k);
    assert.deepEqual([r.json.vehicle.pickerl_month, r.json.vehicle.pickerl_year], [6, 2028]);

    // the even older PUT without Pickerl keys keeps Pickerl and the garage fields
    const legacy = await call("PUT", `/api/user/vehicles/${v.id}`, u.token, { make: "VW", model: "Polo", reg_month: 3, reg_year: 2015 });
    assert.deepEqual([legacy.json.vehicle.pickerl_month, legacy.json.vehicle.pickerl_year, legacy.json.vehicle.plate], [6, 2028, "W-1 AB"]);
  });

  test("PUT with the new keys changes them; explicit null clears; odometer is not changed by PUT", async () => {
    const u = await registerUser(base, "d");
    const v = await newVehicle(u.token, { plate: "W-2 CD", current_km: 50000, timing_drive: "belt" });
    const r = await call("PUT", `/api/user/vehicles/${v.id}`, u.token, {
      make: "VW", model: "Golf", reg_month: 3, reg_year: 2015, plate: null, timing_drive: "unknown", odometer_reminder: true, current_km: 1,
    });
    assert.equal(r.status, 200);
    assert.equal(r.json.vehicle.plate, null);
    assert.equal(r.json.vehicle.timing_drive, "unknown");
    assert.equal(r.json.vehicle.odometer_reminder, 1);
    assert.equal(r.json.vehicle.current_km, 50000, "PUT never moves the odometer");
    const bad = await call("PUT", `/api/user/vehicles/${v.id}`, u.token, { make: "VW", timing_drive: "x" });
    assert.deepEqual([bad.status, bad.json.error], [400, "INVALID_TIMING_DRIVE"]);
  });

  // ---------- vehicle limit + duplicates ----------
  test("at most 5 vehicles; a resent create (same client_ref) returns the same vehicle and never a duplicate", async () => {
    const u = await registerUser(base, "e");
    const first = await call("POST", "/api/user/vehicles", u.token, { make: "A", client_ref: "veh-ref-0001" });
    assert.equal(first.status, 201);
    const again = await call("POST", "/api/user/vehicles", u.token, { make: "A", client_ref: "veh-ref-0001" });
    assert.equal(again.status, 200);
    assert.equal(again.json.replayed, true);
    assert.equal(again.json.vehicle.id, first.json.vehicle.id);

    // two identical requests at the same moment
    const [p1, p2] = await Promise.all([
      call("POST", "/api/user/vehicles", u.token, { make: "B", client_ref: "veh-ref-0002" }),
      call("POST", "/api/user/vehicles", u.token, { make: "B", client_ref: "veh-ref-0002" }),
    ]);
    assert.equal(p1.json.vehicle.id, p2.json.vehicle.id);

    for (let i = 0; i < 3; i++) await newVehicle(u.token, { make: `C${i}` });
    const list = await call("GET", "/api/user/vehicles", u.token);
    assert.equal(list.json.vehicles.length, 5);

    const sixth = await call("POST", "/api/user/vehicles", u.token, { make: "F" });
    assert.deepEqual([sixth.status, sixth.json], [409, { ok: false, error: "VEHICLE_LIMIT", limit: 5 }]);
    // a replay of an existing create still answers at the limit
    const replay = await call("POST", "/api/user/vehicles", u.token, { make: "A", client_ref: "veh-ref-0001" });
    assert.equal(replay.status, 200);
    assert.equal((await call("GET", "/api/user/vehicles", u.token)).json.vehicles.length, 5);
  });

  // ---------- service plans ----------
  test("service plans: km only, months only, both; keep-if-absent; one plan per kind; delete", async () => {
    const u = await registerUser(base, "f");
    const v = await newVehicle(u.token);
    const p = `/api/user/vehicles/${v.id}/service-plans`;

    let r = await call("PUT", `${p}/oil`, u.token, { interval_km: 15000, interval_months: 12 });
    assert.equal(r.status, 200);
    assert.deepEqual(
      { km: r.json.plan.interval_km, m: r.json.plan.interval_months, d: r.json.plan.remind_days_before },
      { km: 15000, m: 12, d: 30 },
      "default warning: 30 days"
    );

    r = await call("PUT", `${p}/oil`, u.token, { interval_months: null, remind_days_before: 14 });
    assert.deepEqual([r.json.plan.interval_km, r.json.plan.interval_months, r.json.plan.remind_days_before], [15000, null, 14], "km only, km kept");

    r = await call("PUT", `${p}/oil`, u.token, { interval_km: 12345 }); // custom value
    assert.equal(r.json.plan.interval_km, 12345);
    assert.equal(r.json.plan.remind_days_before, 14, "absent key keeps value");

    r = await call("PUT", `${p}/major`, u.token, { interval_months: 60 });
    assert.deepEqual([r.json.plan.interval_km, r.json.plan.interval_months], [null, 60], "months only");

    // repeating the same request: still one plan per kind
    await call("PUT", `${p}/major`, u.token, { interval_months: 60 });
    const all = await call("GET", p, u.token);
    assert.deepEqual(Object.keys(all.json.plans).sort(), ["major", "oil"]);
    assert.equal(all.json.plans.major.interval_months, 60);

    r = await call("PUT", `${p}/major`, u.token, { interval_months: null });
    assert.deepEqual([r.status, r.json.error], [400, "INTERVAL_REQUIRED"], "never a plan without any interval");

    for (const [json, code] of [
      [{ interval_km: 100 }, "INVALID_INTERVAL_KM"],
      [{ interval_km: 600000 }, "INVALID_INTERVAL_KM"],
      [{ interval_km: "15.000" }, "INVALID_INTERVAL_KM"],
      [{ interval_months: 0 }, "INVALID_INTERVAL_MONTHS"],
      [{ interval_months: 241 }, "INVALID_INTERVAL_MONTHS"],
      [{ interval_months: 12, remind_days_before: 10 }, "INVALID_REMIND_DAYS"],
    ]) {
      const b = await call("PUT", `${p}/oil`, u.token, json);
      assert.deepEqual([b.status, b.json.error], [400, code], JSON.stringify(json));
    }
    for (const d of [7, 14, 30, 60]) assert.equal((await call("PUT", `${p}/oil`, u.token, { remind_days_before: d })).json.plan.remind_days_before, d);

    const badKind = await call("PUT", `${p}/brakes`, u.token, { interval_km: 10000 });
    assert.deepEqual([badKind.status, badKind.json.error], [400, "INVALID_KIND"]);
    const noPlan = await call("PUT", `${p}/major`, (await registerUser(base, "f2")).token, { interval_km: 10000 });
    assert.equal(noPlan.status, 403, "another user's vehicle");

    r = await call("DELETE", `${p}/major`, u.token);
    assert.deepEqual(r.json.plans.major, null);
    assert.equal(r.json.plans.oil.interval_km, 12345);
  });

  // ---------- service history ----------
  test("service history: every service is kept, newest first; older entries can be added", async () => {
    const u = await registerUser(base, "g");
    const v = await newVehicle(u.token);
    const p = `/api/user/vehicles/${v.id}/service-records`;

    const a = await call("POST", p, u.token, { kind: "oil", service_date: "2024-03-15", km: 105000, items: ["oil_filter", "engine_oil"], oil_spec: "5W-30 VW 504.00" });
    assert.equal(a.status, 201);
    assert.deepEqual(a.json.record.items, ["engine_oil", "oil_filter"], "stored in a fixed order");
    assert.equal(a.json.record.oil_spec, "5W-30 VW 504.00");

    const b = await call("POST", p, u.token, { kind: "oil", service_date: "2025-03-15", km: 120000, items: ["engine_oil", "oil_filter", "air_filter", "cabin_filter", "fuel_filter"], note: "Werkstatt X" });
    const old = await call("POST", p, u.token, { kind: "oil", service_date: "2016-05-01", km: 30000 }); // an old service entered later
    const chain = await call("POST", p, u.token, { kind: "major", service_date: "2023-01-10", km: 98000, items: ["timing_chain", "water_pump"], note: "Kette gelängt" });
    assert.equal(chain.status, 201);
    assert.deepEqual(chain.json.record.items, ["timing_chain", "water_pump"]);

    const list = await call("GET", p, u.token);
    assert.deepEqual(list.json.records.map((r) => r.service_date), ["2025-03-15", "2024-03-15", "2023-01-10", "2016-05-01"]);
    const oilOnly = await call("GET", `${p}?kind=oil`, u.token);
    assert.equal(oilOnly.json.records.length, 3);
    assert.equal((await call("GET", `${p}?kind=nope`, u.token)).status, 400);

    const detail = await call("GET", `${p}/${b.json.record.id}`, u.token);
    assert.equal(detail.json.record.note, "Werkstatt X");
    assert.equal(detail.json.record.items.length, 5);
    assert.ok(old.json.record.id);
  });

  test("service records are validated: dates, km, items per kind, oil spec, note", async () => {
    const u = await registerUser(base, "h");
    const v = await newVehicle(u.token);
    const p = `/api/user/vehicles/${v.id}/service-records`;
    const cases = [
      [{ kind: "brakes", service_date: "2024-01-01" }, "INVALID_KIND"],
      [{ kind: "oil" }, "INVALID_DATE"],
      [{ kind: "oil", service_date: "2024-02-30" }, "INVALID_DATE"],
      [{ kind: "oil", service_date: "15.03.2024" }, "INVALID_DATE"],
      [{ kind: "oil", service_date: "1949-12-31" }, "INVALID_DATE"],
      [{ kind: "oil", service_date: viennaDate(3) }, "DATE_IN_FUTURE"],
      [{ kind: "oil", service_date: "2024-01-01", km: -5 }, "INVALID_KM"],
      [{ kind: "oil", service_date: "2024-01-01", km: "120.000" }, "INVALID_KM"],
      [{ kind: "oil", service_date: "2024-01-01", items: ["timing_belt"] }, "INVALID_ITEMS"],
      [{ kind: "major", service_date: "2024-01-01", items: ["oil_filter"] }, "INVALID_ITEMS"],
      [{ kind: "oil", service_date: "2024-01-01", items: "oil_filter" }, "INVALID_ITEMS"],
      [{ kind: "major", service_date: "2024-01-01", oil_spec: "5W-30" }, "INVALID_OIL_SPEC"],
      [{ kind: "oil", service_date: "2024-01-01", oil_spec: "x".repeat(61) }, "INVALID_OIL_SPEC"],
      [{ kind: "oil", service_date: "2024-01-01", note: "x".repeat(1001) }, "INVALID_NOTE"],
    ];
    for (const [json, code] of cases) {
      const r = await call("POST", p, u.token, json);
      assert.deepEqual([r.status, r.json], [400, { ok: false, error: code }], JSON.stringify(json));
    }
    // today is fine (and km is optional — e.g. an old time-based service)
    const today = await call("POST", p, u.token, { kind: "oil", service_date: viennaDate(0) });
    assert.equal(today.status, 201);
    assert.equal(today.json.record.km, null);
    assert.equal((await call("GET", p, u.token)).json.records.length, 1, "only the valid one was stored");
  });

  test("editing a record keeps other records and the plan; kind can't change; delete removes only that record", async () => {
    const u = await registerUser(base, "i");
    const v = await newVehicle(u.token);
    const p = `/api/user/vehicles/${v.id}/service-records`;
    await call("PUT", `/api/user/vehicles/${v.id}/service-plans/oil`, u.token, { interval_km: 15000, interval_months: 12 });
    const older = await call("POST", p, u.token, { kind: "oil", service_date: "2024-03-15", km: 105000 });
    const newest = await call("POST", p, u.token, { kind: "oil", service_date: "2025-03-15", km: 120000, note: "a" });

    // edit the newest: only the sent keys change
    const e = await call("PUT", `${p}/${newest.json.record.id}`, u.token, { service_date: "2025-04-01", items: ["oil_filter"] });
    assert.equal(e.status, 200);
    assert.deepEqual([e.json.record.service_date, e.json.record.km, e.json.record.note, e.json.record.items], ["2025-04-01", 120000, "a", ["oil_filter"]]);
    const k = await call("PUT", `${p}/${newest.json.record.id}`, u.token, { kind: "major" });
    assert.deepEqual([k.status, k.json.error], [400, "KIND_IMMUTABLE"]);
    const bad = await call("PUT", `${p}/${newest.json.record.id}`, u.token, { service_date: "2025-13-01" });
    assert.deepEqual([bad.status, bad.json.error], [400, "INVALID_DATE"]);

    // delete the newest: the older one becomes the newest again, the plan is unchanged
    const d = await call("DELETE", `${p}/${newest.json.record.id}`, u.token);
    assert.deepEqual(d.json, { ok: true });
    const after = await call("GET", `/api/user/vehicles/${v.id}/services`, u.token);
    assert.deepEqual(after.json.records.map((r) => r.id), [older.json.record.id]);
    assert.deepEqual([after.json.plans.oil.interval_km, after.json.plans.oil.interval_months], [15000, 12]);
    assert.equal((await call("DELETE", `${p}/${newest.json.record.id}`, u.token)).status, 404, "already gone");
    assert.equal((await call("GET", `${p}/${newest.json.record.id}`, u.token)).status, 404);
  });

  test("a resent 'service done' (same client_ref) never creates a second record", async () => {
    const u = await registerUser(base, "j");
    const v = await newVehicle(u.token);
    const v2 = await newVehicle(u.token, { make: "Audi" });
    const p = `/api/user/vehicles/${v.id}/service-records`;
    const body = { kind: "oil", service_date: "2025-01-05", km: 80000, client_ref: "svc-done-0001" };
    const r1 = await call("POST", p, u.token, body);
    const r2 = await call("POST", p, u.token, body);
    assert.deepEqual([r1.status, r2.status, r2.json.replayed], [201, 200, true]);
    assert.equal(r2.json.record.id, r1.json.record.id);

    const [c1, c2] = await Promise.all([
      call("POST", p, u.token, { ...body, client_ref: "svc-done-0002" }),
      call("POST", p, u.token, { ...body, client_ref: "svc-done-0002" }),
    ]);
    assert.equal(c1.json.record.id, c2.json.record.id);
    assert.equal((await call("GET", p, u.token)).json.records.length, 2);

    const conflict = await call("POST", `/api/user/vehicles/${v2.id}/service-records`, u.token, body);
    assert.deepEqual([conflict.status, conflict.json.error], [409, "CLIENT_REF_CONFLICT"]);
    assert.equal((await call("GET", `/api/user/vehicles/${v2.id}/service-records`, u.token)).json.records.length, 0);
  });

  test("record limit per vehicle", async () => {
    const u = await registerUser(base, "lim");
    const v = await newVehicle(u.token);
    const p = `/api/user/vehicles/${v.id}/service-records`;
    for (let i = 0; i < 500; i++) {
      const r = await call("POST", p, u.token, { kind: "oil", service_date: "2020-01-01", km: i });
      assert.equal(r.status, 201);
    }
    const over = await call("POST", p, u.token, { kind: "oil", service_date: "2020-01-01" });
    assert.deepEqual([over.status, over.json], [409, { ok: false, error: "RECORD_LIMIT", limit: 500 }]);
  });

  // ---------- odometer ----------
  test("odometer: update, guarded decrease, services move it up but never down", async () => {
    const u = await registerUser(base, "k");
    const v = await newVehicle(u.token, { current_km: 100000 });
    const o = `/api/user/vehicles/${v.id}/odometer`;

    let r = await call("PATCH", o, u.token, { km: 101500 });
    assert.equal(r.json.vehicle.current_km, 101500);
    assert.ok(r.json.vehicle.current_km_at >= v.current_km_at);

    r = await call("PATCH", o, u.token, { km: 99000 });
    assert.deepEqual([r.status, r.json], [409, { ok: false, error: "ODOMETER_DECREASE", known_km: 101500 }]);
    r = await call("PATCH", o, u.token, { km: 99000, confirm_decrease: true });
    assert.equal(r.json.vehicle.current_km, 99000);

    for (const [json, code] of [[{}, "INVALID_KM"], [{ km: "abc" }, "INVALID_KM"], [{ km: 3000000 }, "INVALID_KM"], [{ km: 99000, confirm_decrease: "yes" }, "INVALID_INPUT"]]) {
      const b = await call("PATCH", o, u.token, json);
      assert.deepEqual([b.status, b.json.error], [400, code], JSON.stringify(json));
    }

    // a service at a higher km raises the reading
    const s = await call("POST", `/api/user/vehicles/${v.id}/service-records`, u.token, { kind: "oil", service_date: "2025-06-01", km: 110000 });
    assert.equal(s.json.vehicle.current_km, 110000);
    // an older service at a lower km doesn't lower it
    const old = await call("POST", `/api/user/vehicles/${v.id}/service-records`, u.token, { kind: "oil", service_date: "2020-06-01", km: 50000 });
    assert.equal(old.json.vehicle.current_km, 110000);
    // a reading below a recorded service needs confirmation too
    const below = await call("PATCH", o, u.token, { km: 105000 });
    assert.deepEqual([below.status, below.json.known_km], [409, 110000]);
    // deleting the record leaves the reading as it is
    await call("DELETE", `/api/user/vehicles/${v.id}/service-records/${s.json.record.id}`, u.token);
    assert.equal((await call("GET", "/api/user/vehicles", u.token)).json.vehicles[0].current_km, 110000);
  });

  // ---------- several vehicles / several users ----------
  test("several vehicles of one user have separate plans and histories; /garage returns all", async () => {
    const u = await registerUser(base, "l");
    const a = await newVehicle(u.token, { make: "VW" });
    const b = await newVehicle(u.token, { make: "Audi", timing_drive: "chain" });
    await call("PUT", `/api/user/vehicles/${a.id}/service-plans/oil`, u.token, { interval_km: 15000 });
    await call("PUT", `/api/user/vehicles/${b.id}/service-plans/oil`, u.token, { interval_months: 24 });
    await call("POST", `/api/user/vehicles/${a.id}/service-records`, u.token, { kind: "oil", service_date: "2025-01-01", km: 1000 });
    await call("POST", `/api/user/vehicles/${b.id}/service-records`, u.token, { kind: "major", service_date: "2024-01-01", items: ["timing_chain"] });
    await call("POST", `/api/user/vehicles/${b.id}/service-records`, u.token, { kind: "oil", service_date: "2024-06-01" });

    const g = await call("GET", "/api/user/garage", u.token);
    assert.equal(g.json.limit, 5);
    const byMake = Object.fromEntries(g.json.vehicles.map((x) => [x.vehicle.make, x]));
    assert.deepEqual([byMake.VW.plans.oil.interval_km, byMake.VW.plans.oil.interval_months], [15000, null]);
    assert.deepEqual([byMake.Audi.plans.oil.interval_km, byMake.Audi.plans.oil.interval_months], [null, 24]);
    assert.equal(byMake.VW.records.length, 1);
    assert.equal(byMake.Audi.records.length, 2);
    assert.ok(byMake.VW.records.every((r) => r.vehicle_id === a.id));
  });

  test("another user can't read or change anything in my garage", async () => {
    const owner = await registerUser(base, "m");
    const other = await registerUser(base, "n");
    const v = await newVehicle(owner.token, { plate: "W-9 ZZ", current_km: 5000 });
    const ov = await newVehicle(other.token);
    await call("PUT", `/api/user/vehicles/${v.id}/service-plans/oil`, owner.token, { interval_km: 15000 });
    const rec = await call("POST", `/api/user/vehicles/${v.id}/service-records`, owner.token, { kind: "oil", service_date: "2025-01-01", km: 5000, note: "private" });
    const rid = rec.json.record.id;
    const base_ = `/api/user/vehicles/${v.id}`;

    const attempts = [
      ["GET", `${base_}/services`],
      ["GET", `${base_}/service-plans`],
      ["PUT", `${base_}/service-plans/oil`, { interval_km: 10000 }],
      ["DELETE", `${base_}/service-plans/oil`],
      ["GET", `${base_}/service-records`],
      ["POST", `${base_}/service-records`, { kind: "oil", service_date: "2025-01-01" }],
      ["GET", `${base_}/service-records/${rid}`],
      ["PUT", `${base_}/service-records/${rid}`, { note: "hacked" }],
      ["DELETE", `${base_}/service-records/${rid}`],
      ["PATCH", `${base_}/odometer`, { km: 1, confirm_decrease: true }],
      ["PUT", base_, { make: "Hacked", plate: "X" }],
      ["DELETE", base_],
    ];
    for (const [m, p, json] of attempts) {
      const r = await call(m, p, other.token, json);
      assert.deepEqual([r.status, r.json], [403, { ok: false, error: "FORBIDDEN" }], `${m} ${p}`);
    }
    // my own vehicle id + someone else's record id: simply not found
    for (const m of ["GET", "PUT", "DELETE"]) {
      const r = await call(m, `/api/user/vehicles/${ov.id}/service-records/${rid}`, other.token, m === "PUT" ? { note: "x" } : undefined);
      assert.equal(r.status, 404, m);
    }
    // nothing leaks through /garage
    const g = await call("GET", "/api/user/garage", other.token);
    assert.deepEqual(g.json.vehicles.map((x) => x.vehicle.id), [ov.id]);

    // owner's data is unchanged
    const mine = await call("GET", `${base_}/services`, owner.token);
    assert.equal(mine.json.records[0].note, "private");
    assert.equal(mine.json.plans.oil.interval_km, 15000);
    assert.equal(mine.json.vehicle.current_km, 5000);
    assert.equal(mine.json.vehicle.plate, "W-9 ZZ");

    // no token / a company token / a forged token
    assert.equal((await api(base, "GET", "/api/user/garage")).status, 401);
    assert.equal((await api(base, "GET", `${base_}/services`, { token: "forged.token.value" })).status, 401);
    const co = await api(base, "POST", "/api/auth/register-company", {
      headers: ip(),
      json: { companyName: `Garage Co ${n}`, phone: "+43 660 1234567", address: "A 1, 1010 Wien", email: `co.${n}@example.at`, password: "rightpass1", categories: ["repair"] },
    });
    assert.equal((await api(base, "GET", `${base_}/services`, { token: co.json.token })).status, 401);
    assert.equal((await api(base, "GET", "/api/user/vehicles/abc/services", { token: owner.token })).status, 400);
    assert.equal((await api(base, "GET", "/api/user/vehicles/999999/services", { token: owner.token })).status, 404);
  });

  // ---------- deleting ----------
  test("deleting a vehicle removes its plans and history; other vehicles are untouched", async () => {
    const u = await registerUser(base, "o");
    const a = await newVehicle(u.token, { make: "VW" });
    const b = await newVehicle(u.token, { make: "Audi" });
    for (const v of [a, b]) {
      await call("PUT", `/api/user/vehicles/${v.id}/service-plans/oil`, u.token, { interval_km: 15000 });
      await call("POST", `/api/user/vehicles/${v.id}/service-records`, u.token, { kind: "oil", service_date: "2025-01-01" });
    }
    assert.deepEqual((await call("DELETE", `/api/user/vehicles/${a.id}`, u.token)).json, { ok: true });
    const g = await call("GET", "/api/user/garage", u.token);
    assert.deepEqual(g.json.vehicles.map((x) => x.vehicle.id), [b.id]);
    assert.equal(g.json.vehicles[0].records.length, 1);
    assert.equal(g.json.vehicles[0].plans.oil.interval_km, 15000);
    assert.equal((await call("GET", `/api/user/vehicles/${a.id}/services`, u.token)).status, 404);
  });

  test("deleting the account removes every vehicle, plan and record; the same e-mail starts with an empty garage", async () => {
    const u = await registerUser(base, "p");
    const v = await newVehicle(u.token);
    await call("PUT", `/api/user/vehicles/${v.id}/service-plans/major`, u.token, { interval_km: 120000, interval_months: 60 });
    await call("POST", `/api/user/vehicles/${v.id}/service-records`, u.token, { kind: "major", service_date: "2024-01-01", items: ["timing_belt"] });
    const other = await registerUser(base, "q");
    const ov = await newVehicle(other.token);
    await call("POST", `/api/user/vehicles/${ov.id}/service-records`, other.token, { kind: "oil", service_date: "2024-01-01" });

    assert.deepEqual((await api(base, "DELETE", "/api/auth/delete-user", { token: u.token })).json, { ok: true });
    assert.equal((await call("GET", "/api/user/garage", u.token)).status, 401, "old token is dead");

    const again = await api(base, "POST", "/api/auth/register-user", {
      headers: ip(),
      json: { firstName: "G", lastName: "T", username: `again${n}`, email: u.email, password: "rightpass1" },
    });
    assert.equal(again.status, 200);
    assert.deepEqual((await call("GET", "/api/user/garage", again.json.token)).json.vehicles, []);
    // the other user's data is untouched
    assert.equal((await call("GET", `/api/user/vehicles/${ov.id}/service-records`, other.token)).json.records.length, 1);
  });

  // ---------- Pickerl ----------
  test("no garage operation changes Pickerl data", async () => {
    const u = await registerUser(base, "r", { car_make: "VW", car_reg_month: 4, car_reg_year: 2019, car_pickerl_month: 4, car_pickerl_year: 2027 });
    const v = (await call("GET", "/api/user/vehicles", u.token)).json.vehicles[0];
    assert.deepEqual([v.pickerl_month, v.pickerl_year], [4, 2027]);
    const p = `/api/user/vehicles/${v.id}`;
    await call("PUT", `${p}/service-plans/oil`, u.token, { interval_km: 15000, interval_months: 12 });
    const rec = await call("POST", `${p}/service-records`, u.token, { kind: "oil", service_date: "2025-01-01", km: 60000 });
    await call("PUT", `${p}/service-records/${rec.json.record.id}`, u.token, { km: 61000 });
    await call("PATCH", `${p}/odometer`, u.token, { km: 62000 });
    await call("PUT", p, u.token, { make: "VW", reg_month: 4, reg_year: 2019, plate: "W-7 PK", timing_drive: "belt" });
    await call("DELETE", `${p}/service-records/${rec.json.record.id}`, u.token);
    await call("DELETE", `${p}/service-plans/oil`, u.token);
    const after = (await call("GET", "/api/user/vehicles", u.token)).json.vehicles[0];
    assert.deepEqual([after.pickerl_month, after.pickerl_year, after.reg_month, after.reg_year], [4, 2027, 4, 2019]);
  });
});

// ---------- compatibility with installed apps + migration ----------
describe("Garage changes are additive for installed apps and for the existing database", () => {
  let head;
  after(() => head?.cleanup());

  // The request sequence of the released app (registration with a car,
  // settings save with and without Pickerl, a second vehicle, deleting it).
  async function oldAppVehicleSequence(base) {
    const log = [];
    const rec = async (step, p) => {
      const r = await p;
      log.push({ step, status: r.status, body: r.json });
      return r;
    };
    const reg = await rec("register", api(base, "POST", "/api/auth/register-user", {
      headers: ip(),
      json: { firstName: "O", lastName: "A", username: "oldapp", email: "old.app@example.at", password: "rightpass1", car_make: "VW", car_model: "Golf", car_reg_month: 3, car_reg_year: 2015 },
    }));
    const t = reg.json.token;
    const vs = await rec("vehicles", api(base, "GET", "/api/user/vehicles", { token: t }));
    const vid = vs.json.vehicles[0].id;
    await rec("put-pickerl", api(base, "PUT", `/api/user/vehicles/${vid}`, { token: t, json: { make: "VW", model: "Golf", reg_month: 3, reg_year: 2015, pickerl_month: 6, pickerl_year: 2028 } }));
    await rec("put-legacy", api(base, "PUT", `/api/user/vehicles/${vid}`, { token: t, json: { make: "VW", model: "Polo", reg_month: 3, reg_year: 2015 } }));
    await rec("put-bad-month", api(base, "PUT", `/api/user/vehicles/${vid}`, { token: t, json: { reg_month: 13 } }));
    await rec("put-bad-pickerl", api(base, "PUT", `/api/user/vehicles/${vid}`, { token: t, json: { pickerl_month: 13, pickerl_year: 2028 } }));
    const second = await rec("post", api(base, "POST", "/api/user/vehicles", { token: t, json: { make: "Audi", pickerl_month: null, pickerl_year: null } }));
    await rec("post-bad-year", api(base, "POST", "/api/user/vehicles", { token: t, json: { make: "X", reg_year: 1800 } }));
    await rec("vehicles-after", api(base, "GET", "/api/user/vehicles", { token: t }));
    await rec("delete-second", api(base, "DELETE", `/api/user/vehicles/${second.json.vehicle.id}`, { token: t }));
    await rec("vehicles-final", api(base, "GET", "/api/user/vehicles", { token: t }));
    return log;
  }

  // Old answers must equal new answers once the new vehicle keys are removed
  // (installed apps ignore unknown keys) and volatile values are normalised.
  function normalize(value, key = "") {
    if (Array.isArray(value)) return value.map((v) => normalize(v));
    if (value && typeof value === "object") {
      const out = {};
      for (const k of Object.keys(value).sort()) {
        if (GARAGE_KEYS.includes(k)) continue;
        out[k] = normalize(value[k], k);
      }
      return out;
    }
    if (typeof value === "string" && /^ey[\w-]+\.[\w-]+\.[\w-]+$/.test(value)) return "<jwt>";
    if (typeof value === "string" && /^u_[0-9a-f]{20}$/.test(value)) return "<u-id>";
    if (["created_at", "updated_at"].includes(key)) return "<time>";
    if (key === "createdAt") return "<ts>";
    return value;
  }

  test("the released app's vehicle requests get the same answers (plus only new keys) as from the live server", async () => {
    head = headIndexCopy(LIVE_BASELINE);
    const oldSrv = await startServer({ script: head.file });
    let oldLog;
    try {
      oldLog = await oldAppVehicleSequence(oldSrv.base);
    } finally {
      await oldSrv.stop();
    }
    const newSrv = await startServer();
    let newLog;
    try {
      newLog = await oldAppVehicleSequence(newSrv.base);
    } finally {
      await newSrv.stop();
    }
    assert.equal(newLog.length, oldLog.length);
    for (let i = 0; i < oldLog.length; i++) {
      assert.deepEqual(normalize(newLog[i]), normalize(oldLog[i]), `step ${oldLog[i].step}`);
    }
    // and the new keys are really there, empty, on the new server
    const v = newLog.find((e) => e.step === "vehicles").body.vehicles[0];
    assert.deepEqual([v.plate, v.current_km, v.timing_drive, v.odometer_reminder], [null, null, null, 0]);
  });

  test("an existing database migrates additively; data and Pickerl survive; the old server still runs on it", async () => {
    head = head || headIndexCopy(LIVE_BASELINE);
    const dbDir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-migrate-"));
    const env = { DB_FILE: path.join(dbDir, "live-copy.sqlite") };
    try {
      // 1) data written by the currently released server
      const old1 = await startServer({ script: head.file, env });
      let token;
      let vid;
      try {
        const reg = await api(old1.base, "POST", "/api/auth/register-user", {
          headers: ip(),
          json: { firstName: "M", lastName: "G", username: "migr", email: "migr@example.at", password: "rightpass1", car_make: "VW", car_reg_month: 5, car_reg_year: 2018, car_pickerl_month: 5, car_pickerl_year: 2027 },
        });
        token = reg.json.token;
        vid = (await api(old1.base, "GET", "/api/user/vehicles", { token })).json.vehicles[0].id;
      } finally {
        await old1.stop();
      }

      // 2) the new server on the same file: everything is still there, garage works
      const nw = await startServer({ env: { ...env, JWT_SECRET: "migration-secret" } });
      let reLogin;
      try {
        reLogin = await api(nw.base, "POST", "/api/auth/login-user", { headers: ip(), json: { email: "migr@example.at", password: "rightpass1" } });
        assert.equal(reLogin.status, 200);
        const t = reLogin.json.token;
        const v = (await api(nw.base, "GET", "/api/user/vehicles", { token: t })).json.vehicles[0];
        assert.deepEqual([v.id, v.make, v.reg_month, v.reg_year, v.pickerl_month, v.pickerl_year], [vid, "VW", 5, 2018, 5, 2027]);
        assert.deepEqual([v.plate, v.current_km, v.timing_drive, v.odometer_reminder], [null, null, null, 0]);
        await api(nw.base, "PUT", `/api/user/vehicles/${vid}`, { token: t, json: { make: "VW", reg_month: 5, reg_year: 2018, plate: "W-5 MG" } });
        await api(nw.base, "POST", `/api/user/vehicles/${vid}/service-records`, { token: t, json: { kind: "oil", service_date: "2025-02-02", km: 70000 } });
      } finally {
        await nw.stop();
      }

      // 3) going back to the released server (rollback) still works on the migrated file
      const old2 = await startServer({ script: head.file, env: { ...env, JWT_SECRET: "rollback-secret" } });
      try {
        const login = await api(old2.base, "POST", "/api/auth/login-user", { headers: ip(), json: { email: "migr@example.at", password: "rightpass1" } });
        assert.equal(login.status, 200);
        const t = login.json.token;
        const v = (await api(old2.base, "GET", "/api/user/vehicles", { token: t })).json.vehicles[0];
        assert.deepEqual([v.pickerl_month, v.pickerl_year, v.plate, v.current_km], [5, 2027, "W-5 MG", 70000]);
        // the released app's settings save on the old server keeps working
        const put = await api(old2.base, "PUT", `/api/user/vehicles/${vid}`, { token: t, json: { make: "VW", model: "Golf", reg_month: 5, reg_year: 2018, pickerl_month: 5, pickerl_year: 2027 } });
        assert.equal(put.status, 200);
      } finally {
        await old2.stop();
      }
    } finally {
      for (let i = 0; i < 20; i++) {
        try {
          fs.rmSync(dbDir, { recursive: true, force: true });
          break;
        } catch {
          await new Promise((r) => setTimeout(r, 100));
        }
      }
    }
  });
});
