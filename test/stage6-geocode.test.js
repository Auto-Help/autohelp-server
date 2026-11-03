// Stage 6: GET /api/geocode — address -> suggested position (never stored).
// A local fake Nominatim records every request; nothing goes to the internet.
"use strict";

const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

const { startServer, api, sleep } = require("./helpers");

// Fake Nominatim: answers by the query text.
function startFakeNominatim() {
  const calls = [];
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    const q = u.searchParams.get("q") || "";
    calls.push({ at: Date.now(), q, ua: req.headers["user-agent"], lang: req.headers["accept-language"], params: Object.fromEntries(u.searchParams) });
    const send = (status, body) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (q.includes("Stephansplatz 1")) return send(200, [{ lat: "48.2084", lon: "16.3731", display_name: "Stephansplatz 1, 1010 Wien, Österreich", place_rank: 30 }]);
    if (q.includes("Kärntner Straße")) return send(200, [{ lat: "48.2040", lon: "16.3708", display_name: "Kärntner Straße, Wien", place_rank: 26 }]);
    if (q.includes("Graz")) return send(200, [{ lat: "47.0707", lon: "15.4395", display_name: "Graz, Steiermark", place_rank: 16 }]);
    if (q.includes("Broken")) return send(500, { error: "boom" });
    if (q.includes("Garbage")) return send(200, [{ lat: "abc", lon: "999", display_name: "x", place_rank: 30 }]);
    if (q.includes("Slow")) return setTimeout(() => send(200, []), 3000);
    return send(200, []);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${server.address().port}`, calls, close: () => new Promise((r) => server.close(r)) })));
}

describe("Geocoding endpoint", () => {
  let fake;
  let srv;
  const geo = (q, opts = {}) =>
    api(srv.base, "GET", `/api/geocode?q=${encodeURIComponent(q)}${opts.lang ? `&lang=${opts.lang}` : ""}`, { headers: opts.headers || {} });

  before(async () => {
    fake = await startFakeNominatim();
    srv = await startServer({ env: { GEOCODER_PROVIDER: "nominatim", NOMINATIM_URL: fake.url, GEOCODER_TIMEOUT_MS: "800", PUBLIC_BASE_URL: "https://api.autohelp.test" } });
  });
  after(async () => {
    await srv.stop();
    await fake.close();
  });

  test("exact address -> one suggestion with precision 'exact'; identifying User-Agent and language sent", async () => {
    const r = await geo("Stephansplatz 1, 1010 Wien, AT", { lang: "de" });
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.results, [{ lat: 48.2084, lng: 16.3731, label: "Stephansplatz 1, 1010 Wien, Österreich", precision: "exact" }]);
    const call = fake.calls.at(-1);
    assert.match(call.ua, /^AutoHelp-Server\/1\.0 \(\+https:\/\/api\.autohelp\.test\)$/);
    assert.equal(call.lang, "de");
    assert.equal(call.params.format, "jsonv2");
  });

  test("street-level and city-level results are marked as approximate", async () => {
    assert.equal((await geo("Kärntner Straße, Wien")).json.results[0].precision, "street");
    assert.equal((await geo("Graz, Österreich")).json.results[0].precision, "area");
  });

  test("not found -> ok with an empty list", async () => {
    const r = await geo("Nowhere Street 999, Atlantis");
    assert.deepEqual([r.status, r.json], [200, { ok: true, results: [] }]);
  });

  test("results with broken coordinates are dropped", async () => {
    const r = await geo("Garbage Road 1, Wien");
    assert.deepEqual(r.json.results, []);
  });

  test("provider error / timeout -> 502 GEOCODER_ERROR (JSON), and errors are not cached", async () => {
    const a = await geo("Broken Gasse 1, Wien");
    assert.deepEqual([a.status, a.json], [502, { ok: false, error: "GEOCODER_ERROR" }]);
    const before = fake.calls.length;
    await geo("Broken Gasse 1, Wien");
    assert.equal(fake.calls.length, before + 1, "retried, not served from cache");
    const t = await geo("Slow Weg 3, Wien");
    assert.deepEqual([t.status, t.json], [502, { ok: false, error: "GEOCODER_ERROR" }]);
  });

  test("same address again is served from the cache (no second provider request)", async () => {
    await geo("Stephansplatz 1, 1010   WIEN, AT");
    const before = fake.calls.length;
    const r = await geo("stephansplatz 1, 1010 wien, at");
    assert.equal(r.json.cached, true);
    assert.equal(fake.calls.length, before);
  });

  test("at most one provider request per second, even for parallel users", async () => {
    const start = fake.calls.length;
    await Promise.all(["Teststraße 1, Wien", "Teststraße 2, Wien", "Teststraße 3, Wien"].map((q, i) => geo(q, { headers: { "X-Forwarded-For": `198.51.100.${i}` } })));
    const times = fake.calls.slice(start).map((c) => c.at);
    assert.equal(times.length, 3);
    for (let i = 1; i < times.length; i++) assert.ok(times[i] - times[i - 1] >= 1000, `gap ${times[i] - times[i - 1]} ms`);
  });

  test("invalid input -> 400 INVALID_ADDRESS, provider not called", async () => {
    const before = fake.calls.length;
    for (const q of ["", "Wien", "x".repeat(301), "Stephansplatz\u0000 1"]) {
      const r = await geo(q);
      assert.deepEqual([r.status, r.json], [400, { ok: false, error: "INVALID_ADDRESS" }], JSON.stringify(q));
    }
    assert.equal(fake.calls.length, before);
  });

  test("the endpoint stores nothing: the company record is unchanged", async () => {
    const reg = await api(srv.base, "POST", "/api/auth/register-company", {
      json: { companyName: "Geo Co", phone: "+43 660 1234567", address: "Stephansplatz 1, 1010 Wien", email: "geo@example.test", password: "rightpass1", categories: ["repair"] },
    });
    await geo("Stephansplatz 1, 1010 Wien");
    const c = await api(srv.base, "GET", `/api/companies/${reg.json.company.id}`);
    assert.deepEqual([c.json.item.lat, c.json.item.lng], [null, null]);
  });
});

describe("Geocoding: busy queue and misuse limits", () => {
  test("too many waiting requests -> 503 GEOCODER_BUSY", async () => {
    const fake = await startFakeNominatim();
    const srv = await startServer({ env: { GEOCODER_PROVIDER: "nominatim", NOMINATIM_URL: fake.url } });
    try {
      const qs = Array.from({ length: 9 }, (_, i) => `Wartestraße ${i + 1}, Wien`);
      const rs = await Promise.all(qs.map((q, i) => api(srv.base, "GET", `/api/geocode?q=${encodeURIComponent(q)}`, { headers: { "X-Forwarded-For": `192.0.2.${i}` } })));
      const busy = rs.filter((r) => r.status === 503);
      assert.ok(busy.length >= 1, `statuses ${rs.map((r) => r.status)}`);
      for (const b of busy) assert.deepEqual(b.json, { ok: false, error: "GEOCODER_BUSY" });
      assert.ok(rs.filter((r) => r.status === 200).length >= 5);
    } finally {
      await srv.stop();
      await fake.close();
    }
  });

  test("per-IP limit: 20 lookups per 15 minutes", async () => {
    const fake = await startFakeNominatim();
    const srv = await startServer({ env: { GEOCODER_PROVIDER: "nominatim", NOMINATIM_URL: fake.url } });
    try {
      for (let i = 0; i < 20; i++) {
        const r = await api(srv.base, "GET", `/api/geocode?q=${encodeURIComponent("Stephansplatz 1, Wien")}`, { headers: { "X-Forwarded-For": "203.0.113.50" } });
        assert.equal(r.status, 200, `call ${i + 1}`);
      }
      const r = await api(srv.base, "GET", `/api/geocode?q=${encodeURIComponent("Stephansplatz 1, Wien")}`, { headers: { "X-Forwarded-For": "203.0.113.50" } });
      assert.equal(r.status, 429);
    } finally {
      await srv.stop();
      await fake.close();
    }
  });

  test("default configuration: the public service is NOT used until switched on", async () => {
    const fake = await startFakeNominatim();
    const srv = await startServer({ env: { NOMINATIM_URL: fake.url } }); // no GEOCODER_PROVIDER
    try {
      const r = await api(srv.base, "GET", `/api/geocode?q=${encodeURIComponent("Stephansplatz 1, Wien")}`);
      assert.deepEqual([r.status, r.json], [503, { ok: false, error: "GEOCODER_UNAVAILABLE" }]);
      await sleep(100);
      assert.equal(fake.calls.length, 0);
    } finally {
      await srv.stop();
      await fake.close();
    }
  });
});
