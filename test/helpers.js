// Test helpers: start an isolated server process, fake SMTP, HTTP + fixtures.
//
// Every server runs from a fresh temp directory (empty SQLite DB + uploads),
// with a minimal environment that is NOT inherited from the shell, and with
// that temp directory as cwd — so the project's real .env (SMTP password
// etc.) is never loaded. E-mail goes only to the in-process fake SMTP below.
"use strict";

const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const http = require("node:http");
const zlib = require("node:zlib");
const crypto = require("node:crypto");

const SERVER_DIR = path.resolve(__dirname, "..");
// AH_TEST_SCRIPT lets the same tests run against another server file (e.g.
// the committed HEAD version) to prove they detect the old problems.
const INDEX = process.env.AH_TEST_SCRIPT ? path.resolve(process.env.AH_TEST_SCRIPT) : path.join(SERVER_DIR, "index.js");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.on("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/** Writes the committed index.js (HEAD, or the given commit) into a temp dir, for old-vs-new comparisons. */
function headIndexCopy(ref = "HEAD") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-head-"));
  const src = execFileSync("git", ["show", `${ref}:index.js`], { cwd: SERVER_DIR });
  const file = path.join(dir, "index.js");
  fs.writeFileSync(file, src);
  return { file, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

const PRELOAD = path.join(__dirname, "preload.js");

/** Polls until fn() is truthy (e.g. a background e-mail has arrived). */
async function waitFor(fn, { timeoutMs = 3000, stepMs = 25 } = {}) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await fn()) return true;
    await sleep(stepMs);
  }
  return !!(await fn());
}

async function startServer({ env = {}, script = INDEX, prepare, fakeClock = false, fsFault } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ah-test-"));
  const uploads = path.join(dir, "uploads");
  fs.mkdirSync(uploads);
  if (prepare) prepare({ dir, uploads });

  const port = await freePort();
  const childEnv = {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    TEMP: process.env.TEMP,
    TMP: process.env.TMP,
    NODE_PATH: path.join(SERVER_DIR, "node_modules"),
    PORT: String(port),
    DB_FILE: path.join(dir, "test.sqlite"),
    UPLOAD_DIR: uploads,
    NODE_ENV: "production",
    JWT_SECRET: `test-only-${crypto.randomBytes(12).toString("hex")}`,
    AH_FAKE_CLOCK: fakeClock ? "1" : undefined,
    AH_FS_FAULT: fsFault,
    ...env,
  };
  for (const k of Object.keys(childEnv)) if (childEnv[k] === undefined) delete childEnv[k];

  const proc = spawn(process.execPath, ["--require", PRELOAD, script], {
    cwd: dir,
    env: childEnv,
    stdio: ["ignore", "pipe", "pipe", ...(fakeClock ? ["ipc"] : [])],
  });
  let logs = "";
  proc.stdout.on("data", (d) => (logs += d));
  proc.stderr.on("data", (d) => (logs += d));
  const exited = new Promise((r) => proc.once("exit", r));

  const base = `http://127.0.0.1:${port}`;
  let up = false;
  for (let i = 0; i < 150 && !up; i++) {
    if (proc.exitCode !== null) break;
    try {
      up = (await fetch(`${base}/api/health`)).ok;
    } catch {}
    if (!up) await sleep(100);
  }
  if (!up) {
    proc.kill();
    throw new Error(`server did not start:\n${logs}`);
  }

  return {
    base,
    dir,
    uploads,
    get logs() {
      return logs;
    },
    /** Moves the server's clock forward (needs fakeClock: true). */
    advance(ms) {
      return new Promise((resolve) => {
        proc.once("message", resolve);
        proc.send({ advanceMs: ms });
      });
    },
    /** Sets the server's clock to an absolute moment, e.g. Date.UTC(...) (needs fakeClock: true). */
    setNow(epochMs) {
      return new Promise((resolve) => {
        proc.once("message", resolve);
        proc.send({ setNow: epochMs });
      });
    },
    async stop() {
      proc.kill();
      await exited;
      for (let i = 0; i < 20; i++) {
        try {
          fs.rmSync(dir, { recursive: true, force: true });
          return;
        } catch {
          await sleep(100); // Windows may hold the SQLite file briefly
        }
      }
    },
  };
}

/** Minimal SMTP sink: accepts everything, stores the message bodies. Sends nothing anywhere. */
async function startFakeSmtp({ greetingDelayMs = 0 } = {}) {
  const mails = [];
  const server = net.createServer((sock) => {
    sock.setEncoding("utf8");
    let buf = "";
    let inData = false;
    let cur = "";
    setTimeout(() => sock.write("220 fake ESMTP\r\n"), greetingDelayMs); // a slow real provider
    sock.on("data", (chunk) => {
      buf += chunk;
      let idx;
      while ((idx = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        if (inData) {
          if (line === ".") {
            inData = false;
            mails.push(cur);
            cur = "";
            sock.write("250 OK\r\n");
          } else {
            cur += `${line}\n`;
          }
          continue;
        }
        const cmd = line.toUpperCase();
        if (cmd.startsWith("EHLO")) sock.write("250-fake\r\n250 AUTH PLAIN\r\n");
        else if (cmd.startsWith("AUTH")) sock.write("235 OK\r\n");
        else if (cmd === "DATA") {
          inData = true;
          sock.write("354 go\r\n");
        } else if (cmd === "QUIT") {
          sock.write("221 bye\r\n");
          sock.end();
        } else sock.write("250 OK\r\n");
      }
    });
    sock.on("error", () => {});
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return {
    port: server.address().port,
    mails,
    close: () => new Promise((r) => server.close(r)),
  };
}

function smtpEnv(smtp) {
  return {
    SMTP_HOST: "127.0.0.1",
    SMTP_PORT: String(smtp.port),
    SMTP_USER: "test",
    SMTP_PASS: "test",
    SMTP_FROM: "AutoHelp Test <test@example.invalid>",
  };
}

/** Decodes quoted-printable soft breaks/escapes so links can be read from a mail body. */
function decodeQP(s) {
  return s.replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function extractResetLink(mail) {
  const m = decodeQP(mail).match(/https?:\/\/[^\s"]+\/reset-password\?token=[0-9a-f]+/);
  return m ? m[0] : null;
}

/** Raw HTTP request with full control over headers (Host, X-Forwarded-*). */
function request(base, { method = "GET", path: p = "/", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(base);
    const req = http.request({ host: u.hostname, port: u.port, method, path: p, headers }, (res) => {
      const chunks = [];
      res.on("data", (d) => chunks.push(d));
      res.on("end", () => {
        const buf = Buffer.concat(chunks);
        const text = buf.toString("utf8");
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {}
        resolve({ status: res.statusCode, headers: res.headers, text, json, buf });
      });
    });
    req.on("error", reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function api(base, method, p, { json, token, headers = {} } = {}) {
  const h = { ...headers };
  let body;
  if (json !== undefined) {
    body = JSON.stringify(json);
    h["Content-Type"] = "application/json";
  }
  if (token) h.Authorization = `Bearer ${token}`;
  return request(base, { method, path: p, headers: h, body });
}

/** Multipart upload the way the dashboard does it (fields "logo" / "images"). */
async function uploadMedia(base, token, files, headers = {}) {
  const form = new FormData();
  for (const f of files) form.append(f.field, new Blob([f.data], { type: f.type }), f.name);
  const resp = await fetch(`${base}/api/company/upload-media`, {
    method: "POST",
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers },
    body: form,
  });
  const text = await resp.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {}
  return { status: resp.status, json, text };
}

// ---------- image fixtures (built in memory, with real header structure) ----------
// Pixel data is not real (it isn't needed: the server reads headers only),
// but every header is laid out exactly as in files from cameras / phones.

function png(width = 1, height = 1) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type, "latin1"), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(zlib.crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", zlib.deflateSync(Buffer.from([0, 255, 0, 0]))),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}
const png1x1 = () => png(1, 1);

// JPEG as a phone camera writes it: SOI, APP1/Exif, SOF0 (dimensions), SOS, scan data, EOI.
function jpeg(width = 4032, height = 3024, size = 2048) {
  const exif = Buffer.concat([Buffer.from([0xff, 0xe1, 0x00, 0x10]), Buffer.from("Exif\0\0", "latin1"), Buffer.alloc(8)]);
  const sof = Buffer.from([0xff, 0xc0, 0x00, 0x11, 0x08, height >> 8, height & 0xff, width >> 8, width & 0xff, 0x03, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
  const sos = Buffer.from([0xff, 0xda, 0x00, 0x0c, 0x03, 1, 0x00, 2, 0x11, 3, 0x11, 0x00, 0x3f, 0x00]);
  const head = Buffer.concat([Buffer.from([0xff, 0xd8]), exif, sof, sos]);
  return Buffer.concat([head, crypto.randomBytes(Math.max(16, size - head.length - 2)), Buffer.from([0xff, 0xd9])]);
}
const jpegExif = (size = 2048) => jpeg(4032, 3024, size); // 12 MP phone photo

function gif(width = 1, height = 1) {
  const lsd = Buffer.alloc(7);
  lsd.writeUInt16LE(width, 0);
  lsd.writeUInt16LE(height, 2);
  return Buffer.concat([Buffer.from("GIF89a", "latin1"), lsd, Buffer.from([0x3b])]);
}
const gif1x1 = () => Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");

// WebP "extended" (VP8X) header, as written by Android / Chrome encoders.
function webp(width = 1080, height = 1920) {
  const vp8x = Buffer.alloc(10);
  vp8x.writeUIntLE(width - 1, 4, 3);
  vp8x.writeUIntLE(height - 1, 7, 3);
  const chunkHead = Buffer.concat([Buffer.from("VP8X", "latin1"), Buffer.from([10, 0, 0, 0])]);
  const payload = Buffer.concat([Buffer.from("WEBP", "latin1"), chunkHead, vp8x, crypto.randomBytes(64)]);
  const size = Buffer.alloc(4);
  size.writeUInt32LE(payload.length);
  return Buffer.concat([Buffer.from("RIFF", "latin1"), size, payload]);
}

// ISO-BMFF / HEIF: ftyp + meta(iprp(ipco(ispe...))) + mdat, like iPhone HEIC.
function box(type, ...parts) {
  const body = Buffer.concat(parts);
  const size = Buffer.alloc(4);
  size.writeUInt32BE(8 + body.length);
  return Buffer.concat([size, Buffer.from(type, "latin1"), body]);
}
function ispe(w, h) {
  const b = Buffer.alloc(12); // version/flags + width + height
  b.writeUInt32BE(w, 4);
  b.writeUInt32BE(h, 8);
  return box("ispe", b);
}
function heif(major, compat, sizes) {
  const ftyp = box("ftyp", Buffer.from([major, "\0\0\0\0", ...compat].join(""), "latin1"));
  const ipco = box("ipco", ...sizes.map(([w, h]) => ispe(w, h)));
  const meta = box("meta", Buffer.alloc(4), box("hdlr", Buffer.alloc(4), Buffer.from("pict", "latin1"), Buffer.alloc(13)), box("iprp", ipco));
  return Buffer.concat([ftyp, meta, box("mdat", crypto.randomBytes(256))]);
}
const IPHONE_BRANDS = ["mif1", "MiHE", "miaf", "MiHB", "heic"];
// iPhone layout: 512x512 grid tiles first, a thumbnail, then the full picture.
const heicIphone = (w = 4032, h = 3024) => heif("heic", IPHONE_BRANDS, [[512, 512], [320, 240], [w, h]]);
const heifGeneric = () => heif("mif1", ["mif1", "miaf"], [[1920, 1080]]);
const heicNoSize = () => heif("heic", IPHONE_BRANDS, []); // no ispe: dimensions unknown
const avif = () => heif("avif", ["avif", "mif1", "miaf"], [[1000, 1000]]);

module.exports = {
  SERVER_DIR,
  INDEX,
  sleep,
  waitFor,
  headIndexCopy,
  startServer,
  startFakeSmtp,
  smtpEnv,
  extractResetLink,
  request,
  api,
  uploadMedia,
  fixtures: { png, png1x1, jpeg, jpegExif, gif, gif1x1, webp, heicIphone, heifGeneric, heicNoSize, avif },
};
