// Stage 1 follow-up: image dimensions (pixel bombs), damaged files, normal
// phone photos, parallel uploads. Limits: 12 000 px per side AND 60 MP.
"use strict";

const { describe, test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");

const { startServer, api, uploadMedia, fixtures: f } = require("./helpers");

describe("Image size and integrity checks", () => {
  let srv;
  let token;
  let companyId;

  before(async () => {
    srv = await startServer({ env: { PUBLIC_BASE_URL: "https://api.autohelp.test" } });
    const r = await api(srv.base, "POST", "/api/auth/register-company", {
      json: { companyName: "Img Co", phone: "+43 660 1234567", address: "A 1, 1010 Wien", email: "img@example.test", password: "rightpass1", categories: ["repair"] },
    });
    token = r.json.token;
    companyId = r.json.company.id;
  });
  after(async () => srv.stop());

  const files = () => fs.readdirSync(srv.uploads).sort();
  const upLogo = (data, name = "x", type = "image/*") => uploadMedia(srv.base, token, [{ field: "logo", data, type, name }]);

  // --- normal photos from current phones must pass ---
  const normal = [
    ["JPEG 12 MP (4032x3024, typical phone)", () => f.jpeg(4032, 3024), ".jpg"],
    ["JPEG 48 MP (8064x6048, iPhone 48 MP mode)", () => f.jpeg(8064, 6048), ".jpg"],
    ["JPEG 50 MP (8160x6120, Samsung/Pixel 50 MP mode)", () => f.jpeg(8160, 6120), ".jpg"],
    ["JPEG 50 MP portrait (6120x8160)", () => f.jpeg(6120, 8160), ".jpg"],
    ["HEIC 12 MP iPhone (tiles + thumbnail + 4032x3024)", () => f.heicIphone(4032, 3024), ".heic"],
    ["HEIC 48 MP iPhone (8064x6048)", () => f.heicIphone(8064, 6048), ".heic"],
    ["HEIF mif1 (1920x1080)", () => f.heifGeneric(), ".heif"],
    ["WebP 1080x1920", () => f.webp(1080, 1920), ".webp"],
    ["PNG screenshot 1290x2796", () => f.png(1290, 2796), ".png"],
    ["GIF 640x480", () => f.gif(640, 480), ".gif"],
    ["exactly at the limits: 12000x5000 = 60 MP", () => f.png(12000, 5000), ".png"],
  ];
  for (const [label, make, ext] of normal) {
    test(`accepts ${label}`, async () => {
      const r = await upLogo(make());
      assert.equal(r.status, 200, r.text);
      assert.ok(r.json.logoUrl.endsWith(ext), r.json.logoUrl);
    });
  }

  // --- too large: 400 IMAGE_TOO_LARGE, nothing written ---
  const tooLarge = [
    ["PNG pixel bomb 40000x40000", () => f.png(40000, 40000)],
    ["side over 12000 (12001x100)", () => f.png(12001, 100)],
    ["side over 12000 (100x12001)", () => f.jpeg(100, 12001)],
    ["over 60 MP with both sides under 12000 (8000x7501)", () => f.jpeg(8000, 7501)],
    ["GIF 65535x1", () => f.gif(65535, 1)],
    ["WebP 16000x100", () => f.webp(16000, 100)],
    ["HEIC whose full image is 40000x40000 (behind small tiles)", () => f.heicIphone(40000, 40000)],
    ["HEIC 12001x9000", () => f.heicIphone(12001, 9000)],
  ];
  for (const [label, make] of tooLarge) {
    test(`rejects ${label} -> 400 IMAGE_TOO_LARGE, writes nothing`, async () => {
      const before = files();
      const r = await upLogo(make());
      assert.equal(r.status, 400, r.text);
      assert.deepEqual(r.json, { ok: false, error: "IMAGE_TOO_LARGE" });
      assert.deepEqual(files(), before);
    });
  }

  // --- damaged / unreadable: 400 ONLY_IMAGES_ALLOWED (existing code), nothing written ---
  const damaged = [
    ["truncated JPEG (signature only)", () => Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0])],
    ["JPEG without a frame header (no size)", () => Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x10]), Buffer.from("Exif\0\0", "latin1"), Buffer.alloc(8), Buffer.from([0xff, 0xd9])])],
    ["PNG cut off inside the header", () => f.png(100, 100).subarray(0, 20)],
    ["PNG with 0x0 size", () => f.png(0, 0)],
    ["WebP with invalid VP8X flags", () => {
      const b = f.webp(100, 100);
      b[20] = 0xff;
      return b;
    }],
    ["HEIC without any size information (RISK: see report)", () => f.heicNoSize()],
    ["GIF with only 8 bytes", () => Buffer.from("GIF89a\x01\x00", "latin1")],
  ];
  for (const [label, make] of damaged) {
    test(`rejects ${label} -> 400 ONLY_IMAGES_ALLOWED, writes nothing`, async () => {
      const before = files();
      const r = await upLogo(make());
      assert.equal(r.status, 400, r.text);
      assert.deepEqual(r.json, { ok: false, error: "ONLY_IMAGES_ALLOWED" });
      assert.deepEqual(files(), before);
    });
  }

  test("one oversized image in a batch rejects the whole batch", async () => {
    const before = files();
    const r = await uploadMedia(srv.base, token, [
      { field: "logo", data: f.jpeg(4032, 3024), type: "image/jpeg", name: "ok.jpg" },
      { field: "images", data: f.png(40000, 40000), type: "image/png", name: "bomb.png" },
    ]);
    assert.equal(r.status, 400);
    assert.deepEqual(r.json, { ok: false, error: "IMAGE_TOO_LARGE" });
    assert.deepEqual(files(), before);
  });

  test("parallel uploads: valid ones stored, bombs rejected, gallery capped at 3", async () => {
    await api(srv.base, "POST", "/api/company/update-profile", { token, json: { imagesJson: "[]" } });
    const before = files().length;
    const jobs = [];
    for (let i = 0; i < 4; i++) jobs.push(uploadMedia(srv.base, token, [{ field: "images", data: f.jpeg(4032, 3024), type: "image/jpeg", name: `ok${i}.jpg` }]));
    for (let i = 0; i < 4; i++) jobs.push(uploadMedia(srv.base, token, [{ field: "images", data: f.png(40000, 40000), type: "image/png", name: `b${i}.png` }]));
    const results = await Promise.all(jobs);
    assert.deepEqual(results.slice(0, 4).map((r) => r.status), [200, 200, 200, 200]);
    assert.deepEqual(results.slice(4).map((r) => r.status), [400, 400, 400, 400]);
    assert.equal(files().length - before, 4, "exactly the 4 valid files written");
    const company = await api(srv.base, "GET", `/api/companies/${companyId}`);
    assert.equal(company.json.item.images.length, 3);
  });
});
