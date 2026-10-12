// AutoHelp-server/index.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const morgan = require("morgan");
const helmet = require("helmet");
const fs = require("fs");
const path = require("path");

// ✅ UPLOAD (LOCAL /data/uploads on Render Persistent Disk)
const multer = require("multer");
const { imageSize } = require("image-size");

const app = express();

// Security headers (helmet). Two of its defaults would break the apps and are
// changed on purpose:
//  - no global Content-Security-Policy: the API answers JSON, and the only
//    HTML/files it serves set their own (/uploads, /reset-password);
//  - Cross-Origin-Resource-Policy "cross-origin": the Android/iOS WebViews
//    (https://localhost, capacitor://localhost) load company images from here.
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ======================
// CONFIG (.env)
// ======================
const PORT = process.env.PORT || 4000;

// Web origin (for CORS)
const RAW_APP_BASE_URL = process.env.APP_BASE_URL || "http://localhost:5173";
const looksLikeScheme =
  String(RAW_APP_BASE_URL).includes("://") && !String(RAW_APP_BASE_URL).startsWith("http");

const WEB_ORIGIN =
  process.env.WEB_ORIGIN ||
  process.env.CORS_ORIGIN ||
  (looksLikeScheme ? "http://localhost:5173" : RAW_APP_BASE_URL);

// Deep links
const APP_DEEP_LINK_BASE =
  process.env.APP_DEEP_LINK_BASE || (looksLikeScheme ? RAW_APP_BASE_URL : "autohelp://");

const EXP_DEEP_LINK_BASE = String(process.env.EXP_DEEP_LINK_BASE || "").trim().replace(/\/+$/, "");

// JWT
const NODE_ENV = String(process.env.NODE_ENV || "development").toLowerCase();
const IS_PROD = NODE_ENV === "production";

const JWT_SECRET_RAW = String(process.env.JWT_SECRET || "").trim();
if (IS_PROD && !JWT_SECRET_RAW) {
  console.error("❌ JWT_SECRET is missing in production. Server refused to start.");
  process.exit(1);
}
const JWT_SECRET = JWT_SECRET_RAW || "CHANGE_ME_DEV_SECRET";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "30d";

// SMTP
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;

// DB (Render: use /data + Persistent Disk)
const DB_FILE = process.env.DB_FILE || "/data/autohelp.sqlite";

// Uploads directory (Render persistent disk)
const UPLOAD_DIR = process.env.UPLOAD_DIR || "/data/uploads";

// Reset token config
const RESET_TOKEN_TTL_MS = Number(process.env.RESET_TOKEN_TTL_MS || 30 * 60 * 1000); // 30 min

// Nearby defaults
const DEFAULT_RADIUS_KM = Number(process.env.DEFAULT_RADIUS_KM || 50);

// Public base URL of THIS server, used in password-reset e-mail links and in
// uploaded image URLs. It must never be derived from request headers in
// production (Host / X-Forwarded-Host are client-controlled): otherwise a
// forged header puts an attacker's domain into a real reset e-mail.
// Order: PUBLIC_BASE_URL -> RENDER_EXTERNAL_URL (set by Render itself) ->
// the known production URL. A missing/invalid value only logs a warning; it
// never stops the server from starting.
const PROD_FALLBACK_BASE_URL = "https://autohelp-server.onrender.com";

function parseBaseUrl(raw) {
  const s = String(raw || "").trim();
  if (!s) return null;
  try {
    const u = new URL(s);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    if (u.username || u.password || u.search || u.hash) return null;
    return `${u.origin}${u.pathname}`.replace(/\/+$/, "");
  } catch {
    return null;
  }
}

const PUBLIC_BASE_URL_ENV = parseBaseUrl(process.env.PUBLIC_BASE_URL);
const RENDER_EXTERNAL_URL_ENV = parseBaseUrl(process.env.RENDER_EXTERNAL_URL);
const FIXED_PUBLIC_BASE_URL =
  PUBLIC_BASE_URL_ENV || RENDER_EXTERNAL_URL_ENV || (IS_PROD ? PROD_FALLBACK_BASE_URL : null);

if (String(process.env.PUBLIC_BASE_URL || "").trim() && !PUBLIC_BASE_URL_ENV) {
  console.warn("⚠️ PUBLIC_BASE_URL is not a valid http(s) URL and is ignored.");
}
if (IS_PROD && !PUBLIC_BASE_URL_ENV) {
  console.warn(`⚠️ PUBLIC_BASE_URL is not set; using ${FIXED_PUBLIC_BASE_URL} for links.`);
}

// Reverse proxy. TRUST_PROXY_HOPS = number of proxies in front of the app
// (verify on the real deployment before setting it). When set, req.ip is
// taken from X-Forwarded-For counted from the right, so a client-supplied
// value can't be used to dodge rate limits. When NOT set, the previous
// behaviour (left-most X-Forwarded-For) is kept so real users are never
// lumped together behind one proxy address; the account-based limits below
// protect login and password-reset regardless of the IP.
const TRUST_PROXY_HOPS_RAW = String(process.env.TRUST_PROXY_HOPS || "").trim();
const TRUST_PROXY_HOPS = /^\d+$/.test(TRUST_PROXY_HOPS_RAW) ? Number(TRUST_PROXY_HOPS_RAW) : null;
if (TRUST_PROXY_HOPS !== null) {
  app.set("trust proxy", TRUST_PROXY_HOPS);
} else if (IS_PROD) {
  console.warn("⚠️ TRUST_PROXY_HOPS is not set; IP rate limits use the left-most X-Forwarded-For.");
}

// ======================
// LOGS
// ======================
// Password-reset tokens must never end up in the logs.
morgan.token("safe-url", (req) => String(req.originalUrl || req.url).replace(/([?&]token=)[^&]*/gi, "$1***"));
app.use(morgan(":method :safe-url :status - :response-time ms"));

// ======================
// SIMPLE RATE LIMIT (in-memory)
// ======================
function clientIp(req) {
  if (TRUST_PROXY_HOPS !== null) return String(req.ip || "unknown");
  return String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown")
    .split(",")[0]
    .trim();
}

function createRateLimiter({ windowMs, max, keyPrefix }) {
  const hits = new Map();
  const cleanupEveryMs = Math.max(30_000, Math.floor(windowMs / 2));

  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits.entries()) {
      if (!v || now >= v.resetAt) hits.delete(k);
    }
  }, cleanupEveryMs).unref?.();

  return function rateLimit(req, res, next) {
    const now = Date.now();
    const ip = clientIp(req);
    const key = `${keyPrefix}:${ip}`;

    const v = hits.get(key);
    if (!v || now >= v.resetAt) {
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }

    v.count += 1;
    if (v.count > max) {
      return res.status(429).json({ ok: false, error: "RATE_LIMIT" });
    }
    return next();
  };
}

const rlLogin    = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20, keyPrefix: "login" });
const rlForgot   = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 5,  keyPrefix: "forgot" });
const rlReset    = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, keyPrefix: "reset" });
const rlRegister = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, keyPrefix: "register" });

// Reset e-mails per address, independent of the client IP (which may be forged).
function createKeyLimiter({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits.entries()) {
      if (!v || now >= v.resetAt) hits.delete(k);
    }
  }, Math.max(30_000, Math.floor(windowMs / 2))).unref?.();

  return {
    isBlocked(key) {
      const v = hits.get(key);
      return !!v && Date.now() < v.resetAt && v.count >= max;
    },
    hit(key) {
      const now = Date.now();
      const v = hits.get(key);
      if (!v || now >= v.resetAt) hits.set(key, { count: 1, resetAt: now + windowMs });
      else v.count += 1;
    },
    reset(key) {
      hits.delete(key);
    },
  };
}

const resetMailsPerEmail = createKeyLimiter({ windowMs: 60 * 60 * 1000, max: 3 });

// Progressive throttling of failed password checks (instead of a hard
// lock-out that anyone knowing an e-mail could trigger). The first 5 failures
// are free; after that the next attempt is only accepted after 1, 2, 4, 8, 16,
// 32, 64, then at most 120 seconds — about 40 guesses per hour, the same as
// the former 10-per-15-minutes lock. Earlier attempts get 429 RATE_LIMIT with
// a Retry-After header and the password is not checked. A success, or one
// hour without failures, forgets the failures.
//
// Request handlers check, verify (bcrypt compareSync) and record in one
// synchronous run, so parallel requests can't slip in between.
const THROTTLE_FREE_FAILURES = 5;
const THROTTLE_BASE_DELAY_MS = 1000;
const THROTTLE_MAX_DELAY_MS = 120 * 1000;
const THROTTLE_FORGET_AFTER_MS = 60 * 60 * 1000;

function createFailureThrottle() {
  const state = new Map(); // key -> { failures, lastFailureAt, nextAllowedAt }
  const live = (key, now) => {
    const s = state.get(key);
    if (s && now - s.lastFailureAt >= THROTTLE_FORGET_AFTER_MS) {
      state.delete(key);
      return null;
    }
    return s || null;
  };
  setInterval(() => {
    const now = Date.now();
    for (const key of state.keys()) live(key, now);
  }, 5 * 60 * 1000).unref?.();

  return {
    retryAfterMs(key) {
      const now = Date.now();
      const s = live(key, now);
      if (!s || s.failures < THROTTLE_FREE_FAILURES) return 0;
      return Math.max(0, s.nextAllowedAt - now);
    },
    fail(key) {
      const now = Date.now();
      const s = live(key, now) || { failures: 0 };
      s.failures += 1;
      s.lastFailureAt = now;
      const over = s.failures - THROTTLE_FREE_FAILURES;
      s.nextAllowedAt = over >= 0 ? now + Math.min(THROTTLE_BASE_DELAY_MS * 2 ** over, THROTTLE_MAX_DELAY_MS) : now;
      state.set(key, s);
    },
    clear(key) {
      state.delete(key);
    },
  };
}

const loginThrottle = createFailureThrottle();
const passwordChangeThrottle = createFailureThrottle();

function sendRateLimited(res, retryAfterMs) {
  res.setHeader("Retry-After", String(Math.max(1, Math.ceil(retryAfterMs / 1000))));
  return res.status(429).json({ ok: false, error: "RATE_LIMIT" });
}

// Unknown accounts still cost one bcrypt check, so "no such account" and
// "wrong password" take about the same time.
const DUMMY_PASSWORD_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString("hex"), 10);

// Password check shared by user and company login. Returns true on success;
// otherwise it has already answered 401 INVALID_LOGIN or 429 RATE_LIMIT.
// The answer is the same whether or not the account exists. One counter per
// account: the client IP (forgeable until TRUST_PROXY_HOPS is verified) gives
// no privilege.
function checkLoginPassword(res, accountKey, row, password) {
  const wait = loginThrottle.retryAfterMs(accountKey);
  if (wait > 0) {
    sendRateLimited(res, wait);
    return false;
  }

  const matches = bcrypt.compareSync(password, row ? row.passwordHash : DUMMY_PASSWORD_HASH);
  if (!row || !matches) {
    loginThrottle.fail(accountKey);
    res.status(401).json({ ok: false, error: "INVALID_LOGIN" });
    return false;
  }

  loginThrottle.clear(accountKey);
  return true;
}

// ======================
// CORS
// ======================
function isAllowedOrigin(origin) {
  if (!origin) return true; // native apps / some webviews send no Origin

  const o = String(origin).trim();

  // Allow Capacitor/Ionic app origins (important for iOS/Android WebView)
  if (o === "capacitor://localhost") return true;
  if (o === "ionic://localhost") return true;
  if (o === "http://localhost") return true;
  if (o === "https://localhost") return true;

  // Allow Render preview / localhost in dev
  if (!IS_PROD) {
    if (o.startsWith("http://localhost:")) return true;
    if (o.startsWith("http://127.0.0.1:")) return true;
    if (o.startsWith("https://localhost:")) return true;
  }

  // Allow configured WEB_ORIGIN exact match (web app)
  if (WEB_ORIGIN && (WEB_ORIGIN.startsWith("http://") || WEB_ORIGIN.startsWith("https://"))) {
    return o === WEB_ORIGIN;
  }

  return false;
}

function httpError(status, code) {
  const err = new Error(code);
  err.status = status;
  err.code = code;
  return err;
}

const corsOptions = {
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) return cb(null, true);
    return cb(httpError(403, "CORS_NOT_ALLOWED"), false);
  },
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
};

app.use(cors(corsOptions));

// Preflight (same origin rules as the actual requests)
app.options("*", cors(corsOptions));

// ======================
// UPLOADS: ensure dir + serve static
// ======================
function ensureDir(dir) {
  try {
    fs.mkdirSync(dir, { recursive: true });
  } catch (e) {
    console.error("❌ Cannot create upload dir:", dir, e?.message || e);
  }
}
ensureDir(UPLOAD_DIR);

// Image types served inline. Anything else already on the disk (e.g. a file
// stored by an older version under a client-chosen extension) is only ever
// offered as a download, so it can't run as HTML/SVG on this origin.
const UPLOAD_CONTENT_TYPES = new Map([
  [".jpg", "image/jpeg"],
  [".jpeg", "image/jpeg"],
  [".jfif", "image/jpeg"],
  [".png", "image/png"],
  [".webp", "image/webp"],
  [".gif", "image/gif"],
  [".heic", "image/heic"],
  [".heif", "image/heif"],
]);

// ✅ serve: https://your-server.onrender.com/uploads/<file>
app.use(
  "/uploads",
  (req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Content-Security-Policy", "default-src 'none'; sandbox");
    next();
  },
  express.static(UPLOAD_DIR, {
    maxAge: "7d",
    etag: true,
    index: false,
    dotfiles: "ignore",
    setHeaders: (res, filePath) => {
      const type = UPLOAD_CONTENT_TYPES.get(path.extname(filePath).toLowerCase());
      if (type) {
        res.setHeader("Content-Type", type);
      } else {
        res.setHeader("Content-Type", "application/octet-stream");
        res.setHeader("Content-Disposition", "attachment");
      }
    },
  })
);

function hasUploads() {
  try {
    fs.accessSync(UPLOAD_DIR, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

// The stored type is decided by the file's own bytes (signature), never by
// the client's MIME type or file name. Same formats as before: JPEG, PNG,
// WebP, GIF and HEIC/HEIF (iPhone photos). Returns the extension or null.
const HEIC_BRANDS = new Set(["heic", "heix", "hevc", "hevx", "heim", "heis"]);
const HEIF_BRANDS = new Set(["mif1", "msf1"]);

function detectImageExt(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return null;

  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return ".jpg";
  if (buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return ".png";
  const head6 = buf.toString("latin1", 0, 6);
  if (head6 === "GIF87a" || head6 === "GIF89a") return ".gif";
  if (buf.toString("latin1", 0, 4) === "RIFF" && buf.toString("latin1", 8, 12) === "WEBP") return ".webp";

  // ISO-BMFF: [size][ftyp][major brand][minor version][compatible brands...]
  if (buf.toString("latin1", 4, 8) === "ftyp") {
    const boxSize = Math.min(buf.readUInt32BE(0), buf.length);
    const brands = [buf.toString("latin1", 8, 12)];
    for (let i = 16; i + 4 <= boxSize; i += 4) brands.push(buf.toString("latin1", i, i + 4));
    if (brands.includes("avif") || brands.includes("avis")) return null; // not supported before either
    if (brands.some((b) => HEIC_BRANDS.has(b))) return ".heic";
    if (brands.some((b) => HEIF_BRANDS.has(b))) return ".heif";
  }
  return null;
}

// Pixel limits, checked from the image's own header before anything is
// written. 12 000 px per side and 60 MP cover the 48–50 MP modes of current
// phones (8064×6048, 8160×6120) but stop "pixel bombs" — tiny files that
// claim huge dimensions and exhaust a phone's memory when displayed.
const MAX_IMAGE_SIDE = 12000;
const MAX_IMAGE_PIXELS = 60 * 1000 * 1000;

// image-size reports HEIC/HEIF by the file's major brand (heic, mif1, ...).
const HEIF_MAJOR_BRANDS = ["heic", "heix", "hevc", "hevx", "mif1", "msf1"];
const IMAGE_SIZE_TYPES = {
  ".jpg": ["jpg"],
  ".png": ["png"],
  ".gif": ["gif"],
  ".webp": ["webp"],
  ".heic": HEIF_MAJOR_BRANDS,
  ".heif": HEIF_MAJOR_BRANDS,
};

// Returns null when the image is fine, otherwise the API error code. A file
// whose dimensions can't be read reliably (damaged, truncated, or a HEIC/HEIF
// without size information) is rejected like any other non-image.
function checkImageDimensions(buf, ext) {
  let info;
  try {
    info = imageSize(buf);
  } catch {
    return "ONLY_IMAGES_ALLOWED";
  }
  if (!IMAGE_SIZE_TYPES[ext]?.includes(info?.type)) return "ONLY_IMAGES_ALLOWED";

  // HEIC/HEIF hold several sizes (thumbnail, tiles, full image): the largest counts.
  const sizes = Array.isArray(info.images) && info.images.length ? info.images : [info];
  let maxW = 0;
  let maxH = 0;
  for (const s of sizes) {
    const w = Number(s?.width);
    const h = Number(s?.height);
    if (!Number.isInteger(w) || !Number.isInteger(h) || w < 1 || h < 1) return "ONLY_IMAGES_ALLOWED";
    maxW = Math.max(maxW, w);
    maxH = Math.max(maxH, h);
    if (w * h > MAX_IMAGE_PIXELS) return "IMAGE_TOO_LARGE";
  }
  if (maxW > MAX_IMAGE_SIDE || maxH > MAX_IMAGE_SIDE) return "IMAGE_TOO_LARGE";
  return null;
}

function safeFileName(companyId, kind, ext) {
  const rand = crypto.randomBytes(12).toString("hex");
  const owner = String(companyId || "unknown").replace(/[^A-Za-z0-9_-]/g, "");
  return `${owner}_${kind}_${Date.now()}_${rand}${ext}`;
}

// Files are held in memory, checked, and only then written to UPLOAD_DIR —
// a rejected file never touches the disk. 4 files x 8 MB at most per request.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 4, fields: 20, parts: 30 },
});

// ======================
// DB INIT (SQLite)
// ======================
const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    firstName TEXT NOT NULL,
    lastName TEXT NOT NULL,
    passwordHash TEXT NOT NULL,
    createdAt INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS companies (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    companyName TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT NOT NULL,
    passwordHash TEXT NOT NULL,
    categoriesJson TEXT NOT NULL,
    createdAt INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS ratings (
    id TEXT PRIMARY KEY,
    userId TEXT NOT NULL,
    serviceId TEXT NOT NULL,
    value INTEGER NOT NULL,
    createdAt INTEGER NOT NULL,
    UNIQUE(userId, serviceId)
  );

  CREATE INDEX IF NOT EXISTS idx_ratings_serviceId ON ratings(serviceId);
  CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  CREATE INDEX IF NOT EXISTS idx_companies_email ON companies(email);

  CREATE TABLE IF NOT EXISTS password_resets (
    tokenHash TEXT PRIMARY KEY,
    accountType TEXT NOT NULL CHECK (accountType IN ('user','company')),
    accountId TEXT NOT NULL,
    expiresAt INTEGER NOT NULL,
    createdAt INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_password_resets_expiresAt ON password_resets(expiresAt);
  CREATE INDEX IF NOT EXISTS idx_password_resets_account ON password_resets(accountType, accountId);

  CREATE TABLE IF NOT EXISTS vehicles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL,
    make            TEXT,
    model           TEXT,
    reg_month       INTEGER,
    reg_year        INTEGER,
    gtp_custom_data TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE INDEX IF NOT EXISTS idx_vehicles_user_id ON vehicles(user_id);
`);

function hasColumn(table, col) {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all();
  return rows.some((r) => r.name === col);
}
function addColumnIfMissing(table, colDef) {
  const colName = String(colDef).trim().split(/\s+/)[0];
  if (!hasColumn(table, colName)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${colDef}`);
  }
}

// Companies location & working hours & media (migration)
try {
  addColumnIfMissing("companies", "lat REAL");
  addColumnIfMissing("companies", "lng REAL");
  addColumnIfMissing("companies", "workingHoursJson TEXT");
  addColumnIfMissing("companies", "logoUrl TEXT");
  addColumnIfMissing("companies", "imagesJson TEXT"); // JSON string: ["url1","url2","url3"]

  // ✅ NEW: services text (What do you offer?)
  addColumnIfMissing("companies", "servicesText TEXT");

  // ✅ NEW: profile view counter
  addColumnIfMissing("companies", "viewCount INTEGER DEFAULT 0");
  addColumnIfMissing("companies", "callCount INTEGER DEFAULT 0");
} catch (e) {
  console.log("⚠️ Migration warning:", e?.message || e);
}

// Vehicles Pickerl / §57a fields (migration)
try {
  addColumnIfMissing("vehicles", "pickerl_month INTEGER");
  addColumnIfMissing("vehicles", "pickerl_year INTEGER");
} catch (e) {
  console.log("⚠️ Migration warning:", e?.message || e);
}

// Cleanup expired resets periodically
setInterval(() => {
  try {
    db.prepare("DELETE FROM password_resets WHERE expiresAt <= ?").run(Date.now());
  } catch {}
}, 5 * 60 * 1000).unref?.();

// ======================
// HELPERS
// ======================
function nowMs() {
  return Date.now();
}
function createId(prefix) {
  return `${prefix}_${crypto.randomBytes(10).toString("hex")}`;
}
function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

// Plain mailbox addresses only, as people type them into a form: one "@", no
// spaces, quotes, commas, angle brackets or comments — nothing the mail
// library could read as a display name or a list of recipients (see the open
// nodemailer advisories). At most 254 characters; the local part at most 64.
// Domain labels may use letters of any script (e.g. müller.at).
const EMAIL_LOCAL_RE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*$/i;
const EMAIL_LABEL_RE = /^[\p{L}\p{N}](?:[\p{L}\p{N}-]{0,61}[\p{L}\p{N}])?$/u;
const EMAIL_TLD_RE = /^(?:\p{L}{2,63}|xn--[a-z0-9-]{1,59})$/u;

function isValidEmail(email) {
  const s = String(email || "");
  if (s.length > 254) return false;
  const at = s.indexOf("@");
  if (at < 1 || at !== s.lastIndexOf("@")) return false;
  const local = s.slice(0, at);
  const labels = s.slice(at + 1).split(".");
  if (local.length > 64 || !EMAIL_LOCAL_RE.test(local)) return false;
  if (labels.length < 2 || !labels.every((l) => EMAIL_LABEL_RE.test(l))) return false;
  return EMAIL_TLD_RE.test(labels[labels.length - 1]);
}
function hasSmtp() {
  return !!(SMTP_HOST && SMTP_USER && SMTP_PASS && SMTP_FROM);
}
function getTransporter() {
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}
function sha256Hex(input) {
  return crypto.createHash("sha256").update(String(input)).digest("hex");
}

// Company phones must be international (E.164: "+", country code, number) so
// they can be dialled from any country. Separators people commonly type
// ("+43 660 123-45", "(+49) 30/1234") are stripped and a leading "00" becomes
// "+"; anything that still isn't E.164 is rejected — a country is never guessed.
function normalizePhoneInput(phone) {
  let p = String(phone || "").trim().replace(/[\s\-./()]/g, "");
  if (p.startsWith("00")) p = `+${p.slice(2)}`;
  return p;
}
function isE164Phone(phone) {
  return /^\+[1-9]\d{6,14}$/.test(String(phone || ""));
}

function requireUserAuth(req, res, next) {
  const auth = String(req.headers.authorization || "");
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ ok: false, error: "NO_TOKEN" });

  try {
    const decoded = jwt.verify(m[1], JWT_SECRET);
    if (!decoded || decoded.type !== "user" || !decoded.userId) {
      return res.status(401).json({ ok: false, error: "INVALID_TOKEN" });
    }
    // A token outlives a deleted account (JWTs can't be recalled): the account
    // must still exist. Same error as any other invalid token.
    if (!db.prepare("SELECT 1 FROM users WHERE id = ?").get(String(decoded.userId))) {
      return res.status(401).json({ ok: false, error: "INVALID_TOKEN" });
    }
    req.user = { userId: decoded.userId };
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "INVALID_TOKEN" });
  }
}

function requireCompanyAuth(req, res, next) {
  const auth = String(req.headers.authorization || "");
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ ok: false, error: "NO_TOKEN" });

  try {
    const decoded = jwt.verify(m[1], JWT_SECRET);
    if (!decoded || decoded.type !== "company" || !decoded.companyId) {
      return res.status(401).json({ ok: false, error: "INVALID_TOKEN" });
    }
    if (!db.prepare("SELECT 1 FROM companies WHERE id = ?").get(String(decoded.companyId))) {
      return res.status(401).json({ ok: false, error: "INVALID_TOKEN" });
    }
    req.company = { companyId: decoded.companyId };
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "INVALID_TOKEN" });
  }
}

// Base URL for links and image URLs. Production: always the configured value
// (see FIXED_PUBLIC_BASE_URL) — never Host / X-Forwarded-Host. Local
// development without any configured URL falls back to the Host header so a
// phone on the LAN still gets working image URLs; X-Forwarded-* is ignored.
function getPublicBaseUrl(req) {
  if (FIXED_PUBLIC_BASE_URL) return FIXED_PUBLIC_BASE_URL;
  const host = String(req.get("host") || `localhost:${PORT}`).trim();
  return `http://${host}`.replace(/\/+$/, "");
}

// Returns a bare "scheme:" (no trailing slashes) when the input carries no
// host/authority, so the caller's own "///" separator (see appLink below) is
// always the ONLY source of the 3 slashes in the final canonical
// "scheme:///path" link -- previously, an input that already included "//"
// (e.g. "autohelp://", the most intuitive value to configure) combined with
// the caller's own "///" to produce a malformed 5-slash URL. A host-bearing
// input (e.g. "autohelp://somehost") still returns "scheme://somehost"
// unchanged, preserving that case exactly as before.
function normalizeDeepLinkBase(base) {
  let b = String(base || "").trim();
  if (!b) return "autohelp:";

  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(b)) {
    const idx = b.indexOf("://");
    const scheme = b.slice(0, idx);
    const rest = b.slice(idx + 3).replace(/\/+$/, "");
    return rest ? `${scheme}://${rest}` : `${scheme}:`;
  }

  const stripped = b.replace(/\/+$/, "");
  return stripped.endsWith(":") ? stripped : `${stripped}:`;
}

// A usable coordinate pair, or null. Both values must be present and in range
// (a decimal comma is accepted); (0, 0) means "no position" — no workshop is there.
function parseCoordPair(lat, lng) {
  const toNum = (v) =>
    v === null || v === undefined || v === "" ? NaN : Number(typeof v === "string" ? v.trim().replace(",", ".") : v);
  const la = toNum(lat);
  const ln = toNum(lng);
  if (!Number.isFinite(la) || !Number.isFinite(ln)) return null;
  if (la < -90 || la > 90 || ln < -180 || ln > 180) return null;
  if (la === 0 && ln === 0) return null;
  return { lat: la, lng: ln };
}

// Distance (Haversine)
function haversineKm(lat1, lon1, lat2, lon2) {
  const toRad = (x) => (x * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// ======================
// WORKING HOURS (Europe/Vienna)
// ======================
// Stored as {"mon":[["09:00","18:00"]], ..., "sun":[]} (the dashboard format);
// an older [{day, from, to}] list is still read. Times are local Vienna
// time, whatever the server's own time zone (Render runs on UTC), with
// summer/winter time handled by Intl. A slot is open from its start up to,
// not including, its end. Special cases:
//   "22:00"-"06:00"  overnight: open until 06:00 the next morning
//   "00:00"-"24:00"  the whole day (7 such days = 24/7); "x"-"x" too
// isOpenNow() returns true / false, or null when the hours are unknown.
const BUSINESS_TIME_ZONE = "Europe/Vienna";
const DAY_KEYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
const viennaClockFormat = new Intl.DateTimeFormat("en-US", {
  timeZone: BUSINESS_TIME_ZONE,
  weekday: "short",
  hour: "2-digit",
  minute: "2-digit",
  hourCycle: "h23",
});
const WEEKDAY_INDEX = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

function viennaClock(date) {
  const parts = Object.fromEntries(viennaClockFormat.formatToParts(date).map((p) => [p.type, p.value]));
  return { dayIdx: WEEKDAY_INDEX[parts.weekday], minutes: Number(parts.hour) * 60 + Number(parts.minute) };
}

// "HH:MM" (optionally ":SS") -> minutes since midnight; "24:00" -> 1440; else null.
function parseClockTime(value) {
  const m = String(value ?? "").trim().match(/^(\d{1,2}):(\d{2})(?::\d{2})?$/);
  if (!m) return null;
  const h = Number(m[1]);
  const min = Number(m[2]);
  if (min > 59 || h > 24 || (h === 24 && min !== 0)) return null;
  return h * 60 + min;
}

// -> { mon: [[from, to], ...], ... } in minutes (a missing day stays undefined), or null.
function parseWorkingHours(workingHoursJson) {
  if (!workingHoursJson) return null;
  let data;
  try {
    data = typeof workingHoursJson === "string" ? JSON.parse(workingHoursJson) : workingHoursJson;
  } catch {
    return null;
  }
  const days = {};
  const add = (day, from, to) => {
    const f = parseClockTime(from);
    const t = parseClockTime(to);
    if (f === null || t === null) return;
    days[day].push([f, t]);
  };
  if (data && typeof data === "object" && !Array.isArray(data)) {
    for (const day of DAY_KEYS) {
      if (!Array.isArray(data[day])) continue;
      days[day] = [];
      for (const s of data[day]) if (Array.isArray(s) && s.length >= 2) add(day, s[0], s[1]);
    }
    return days;
  }
  if (Array.isArray(data)) {
    for (const s of data) {
      const day = String(s?.day || "").toLowerCase();
      if (!DAY_KEYS.includes(day)) continue;
      days[day] = days[day] || [];
      add(day, s.from, s.to);
    }
    return days;
  }
  return null;
}

function isOpenNow(workingHoursJson, now = new Date()) {
  const days = parseWorkingHours(workingHoursJson);
  if (!days) return null;
  const { dayIdx, minutes } = viennaClock(now);

  // An overnight slot that started yesterday may still be running.
  for (const [from, to] of days[DAY_KEYS[(dayIdx + 6) % 7]] || []) {
    if (from > to && minutes < to) return true;
  }

  const today = days[DAY_KEYS[dayIdx]];
  if (!today) return null;
  for (const [from, to] of today) {
    if (from === to) return true; // whole day
    if (from < to ? minutes >= from && minutes < to : minutes >= from) return true;
  }
  return false;
}

// Checks hours sent by a client. Returns the string to store, null to clear,
// or undefined when the value isn't valid working hours.
function normalizeWorkingHoursInput(raw) {
  if (raw === null || raw === "") return null;
  let data = raw;
  if (typeof raw === "string") {
    try {
      data = JSON.parse(raw);
    } catch {
      return undefined;
    }
  }
  if (!data || typeof data !== "object" || Array.isArray(data)) return undefined;
  for (const [day, slots] of Object.entries(data)) {
    if (!DAY_KEYS.includes(day) || !Array.isArray(slots) || slots.length > 6) return undefined;
    for (const s of slots) {
      if (!Array.isArray(s) || s.length !== 2) return undefined;
      const from = parseClockTime(s[0]);
      const to = parseClockTime(s[1]);
      if (from === null || to === null || from === 24 * 60) return undefined;
    }
  }
  return typeof raw === "string" ? raw : JSON.stringify(data);
}

// ======================
// CATEGORY NORMALIZATION
// ======================
const CANON_CATEGORIES = new Set(["roadside", "tires", "repair", "wash", "inspection", "towing"]);
const CATEGORY_ALIASES = new Map([
  ["roadside assistance", "roadside"],
  ["roadside-assistance", "roadside"],
  ["пътна помощ", "roadside"],
  ["пътна-помощ", "roadside"],

  ["tire service", "tires"],
  ["tire-service", "tires"],
  ["tyres", "tires"],
  ["гумаджия", "tires"],
  ["гумаджии", "tires"],
  ["гуми", "tires"],

  ["auto repair shop", "repair"],
  ["auto-repair-shop", "repair"],
  ["service", "repair"],
  ["автосервиз", "repair"],
  ["сервиз", "repair"],

  ["car wash", "wash"],
  ["car-wash", "wash"],
  ["carwash", "wash"],
  ["автомивка", "wash"],
  ["мивка", "wash"],

  ["gtp", "inspection"],
  ["гтп", "inspection"],
  ["годишен технически преглед", "inspection"],
  ["годишен-технически-преглед", "inspection"],

  ["tow", "towing"],
  ["repatrak", "towing"],
  ["репатрак", "towing"],
]);

function normalizeCategoryId(input) {
  const raw = String(input || "").trim().toLowerCase();
  if (!raw) return "";
  const cleaned = raw.replace(/[_/]+/g, "-").replace(/\s+/g, " ").trim();

  if (CANON_CATEGORIES.has(cleaned)) return cleaned;
  if (CATEGORY_ALIASES.has(cleaned)) return CATEGORY_ALIASES.get(cleaned);

  const slug = cleaned.replace(/\s+/g, "-");
  if (CANON_CATEGORIES.has(slug)) return slug;
  if (CATEGORY_ALIASES.has(slug)) return CATEGORY_ALIASES.get(slug);

  return slug;
}

function normalizeCategoriesArray(categories) {
  if (!Array.isArray(categories)) return [];
  const out = [];
  for (const c of categories) {
    const n = normalizeCategoryId(c);
    if (!n) continue;
    if (!out.includes(n)) out.push(n);
  }
  return out;
}

function parseCategories(categoriesJson) {
  try {
    const arr = JSON.parse(categoriesJson || "[]");
    const raw = Array.isArray(arr) ? arr.map((x) => String(x)) : [];
    return normalizeCategoriesArray(raw);
  } catch {
    return [];
  }
}

function parseImages(imagesJson) {
  try {
    const arr = JSON.parse(imagesJson || "[]");
    return Array.isArray(arr) ? arr.filter(Boolean).slice(0, 3) : [];
  } catch {
    return [];
  }
}

function getRatingStatsByCompanyId(companyId) {
  const stats = db
    .prepare("SELECT AVG(value) as avg, COUNT(*) as votes FROM ratings WHERE serviceId = ?")
    .get(companyId);
  return {
    average: Number(Number(stats?.avg || 0).toFixed(2)),
    votes: Number(stats?.votes || 0),
  };
}

// ======================
// TEXTS (Forgot/Reset)
// ======================
function msg(lang, key) {
  const L = String(lang || "en").toLowerCase();
  const dict = {
    genericSent: {
      de: "Wenn die E-Mail existiert, senden wir dir einen Link zum Zurücksetzen.",
      en: "If this email exists, you'll receive a reset link.",
      bg: "Ако този имейл съществува, ще получиш линк за смяна на паролата.",
    },
    subject: {
      de: "AutoHelp – Passwort zurücksetzen",
      en: "AutoHelp – Reset your password",
      bg: "AutoHelp – Смяна на парола",
    },
    emailText: {
      de: (link) =>
        `Hallo,\n\nklicke auf diesen Link, um dein Passwort zurückzusetzen:\n${link}\n\nDer Link ist 30 Minuten gültig.\n\nWenn du das nicht warst, ignoriere diese E-Mail.`,
      en: (link) =>
        `Hi,\n\nclick this link to reset your password:\n${link}\n\nThis link is valid for 30 minutes.\n\nIf this wasn't you, ignore this email.`,
      bg: (link) =>
        `Здравей,\n\nнатисни този линк, за да смениш паролата си:\n${link}\n\nЛинкът е валиден 30 минути.\n\nАко не си ти, просто игнорирай този имейл.`,
    },
  };
  const v = Object.hasOwn(dict, key) ? dict[key] : null;
  if (!v) return "";
  if (typeof v === "function") return v;
  // own keys only: a "lang" like "constructor" must not pick Object built-ins
  return Object.hasOwn(v, L) ? v[L] : v.en;
}

// ======================
// HEALTH
// ======================
app.get("/", (req, res) => res.send("AutoHelp server is running ✅"));
app.get("/health", (req, res) => {
  const exists = fs.existsSync(DB_FILE);
  let size = null;
  try {
    size = exists ? fs.statSync(DB_FILE).size : null;
  } catch {}
  res.json({
    ok: true,
    env: NODE_ENV,
    hasSmtp: hasSmtp(),
    hasUploads: hasUploads(),
    // server paths only for local troubleshooting, not on the public server
    ...(IS_PROD ? {} : { uploadDir: UPLOAD_DIR, dbFile: DB_FILE }),
    dbFileExists: exists,
    dbFileSize: size,
    time: new Date().toISOString(),
  });
});
app.get("/api/health", (req, res) => {
  res.status(200).json({
    ok: true,
    status: "up",
    env: NODE_ENV,
    time: new Date().toISOString(),
  });
});
app.head("/api/health", (req, res) => res.sendStatus(200));

// ======================
// ✅ UPLOAD MEDIA (logo + up to 3 images) - LOCAL
// POST /api/company/upload-media
// Fields: logo (1), images (up to 3)
// Auth: company
// Returns public URLs
// ======================
const uploadFields = upload.fields([
  { name: "logo", maxCount: 1 },
  { name: "images", maxCount: 3 },
]);

// A broken multipart body (busboy error) is the client's fault: 400, not 500.
function parseUpload(req, res, next) {
  uploadFields(req, res, (err) => {
    if (!err) return next();
    if (err instanceof multer.MulterError) return next(err);
    return next(httpError(400, "INVALID_UPLOAD"));
  });
}

app.post(
  "/api/company/upload-media",
  requireCompanyAuth,
  parseUpload,
  (req, res) => {
    try {
      if (!hasUploads()) {
        return res.status(500).json({ ok: false, error: "UPLOADS_NOT_AVAILABLE" });
      }

      const companyId = req.company.companyId;
      const base = getPublicBaseUrl(req);

      const logoFile = req.files?.logo?.[0] || null;
      const imageFiles = Array.isArray(req.files?.images) ? req.files.images.slice(0, 3) : [];

      // Check every file first; one bad file rejects the whole request.
      const planned = [];
      for (const [kind, f] of [
        ...(logoFile ? [["logo", logoFile]] : []),
        ...imageFiles.map((f) => ["img", f]),
      ]) {
        const ext = detectImageExt(f.buffer);
        if (!ext) return res.status(400).json({ ok: false, error: "ONLY_IMAGES_ALLOWED" });
        const problem = checkImageDimensions(f.buffer, ext);
        if (problem) return res.status(400).json({ ok: false, error: problem });
        planned.push({ kind, buffer: f.buffer, filename: safeFileName(companyId, kind, ext) });
      }

      const written = [];
      try {
        for (const p of planned) {
          fs.writeFileSync(path.join(UPLOAD_DIR, p.filename), p.buffer, { flag: "wx" });
          written.push(p.filename);
        }
      } catch (e) {
        for (const name of written) {
          try {
            fs.unlinkSync(path.join(UPLOAD_DIR, name));
          } catch {}
        }
        throw e;
      }

      let logoUrl = null;
      const images = [];
      for (const p of planned) {
        const url = `${base}/uploads/${encodeURIComponent(p.filename)}`;
        if (p.kind === "logo") logoUrl = url;
        else images.push(url);
      }

      // merge нови снимки със съществуващите (max 3, без дублиране)
      const existingRow = db.prepare("SELECT imagesJson FROM companies WHERE id = ?").get(companyId);
      let existingImages = [];
      try {
        const parsed = JSON.parse(existingRow?.imagesJson || "[]");
        if (Array.isArray(parsed)) existingImages = parsed.map(String).filter(Boolean);
      } catch {}

      const seen = new Set();
      const mergedImages = [];
      for (const url of [...existingImages, ...images]) {
        if (url && !seen.has(url) && mergedImages.length < 3) {
          seen.add(url);
          mergedImages.push(url);
        }
      }

      db.prepare(
        "UPDATE companies SET logoUrl = COALESCE(?, logoUrl), imagesJson = ? WHERE id = ?"
      ).run(
        logoUrl,
        JSON.stringify(mergedImages),
        companyId
      );

      return res.json({ ok: true, logoUrl, images: mergedImages });
    } catch (e) {
      console.error("upload-media error:", e?.message || e);
      return res.status(500).json({ ok: false, error: "UPLOAD_FAILED" });
    }
  }
);

// ======================
// RESET PASSWORD LANDING PAGE
// ======================
app.get("/reset-password", (req, res) => {
  const token = String(req.query.token || "");
  const deepBase = normalizeDeepLinkBase(APP_DEEP_LINK_BASE);

  const appLink = `${deepBase}///reset-password?token=${encodeURIComponent(token)}`;
  const expoGoLink = EXP_DEEP_LINK_BASE
    ? `${EXP_DEEP_LINK_BASE}/--/reset-password?token=${encodeURIComponent(token)}`
    : "";

  // Own strict CSP: only this page's inline script (by nonce) may run, inline
  // styles are allowed, nothing is loaded from anywhere. Never cached, since
  // the URL carries the reset token.
  const nonce = crypto.randomBytes(16).toString("base64");
  res.setHeader(
    "Content-Security-Policy",
    `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
  );
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AutoHelp – Reset password</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#0b0f14;color:#fff}
.card{max-width:680px;padding:24px;border:1px solid #2a2f3a;border-radius:16px;background:#111827}
a.btn{display:inline-block;margin-top:14px;padding:12px 16px;border-radius:12px;background:#f59e0b;color:#000;text-decoration:none;font-weight:800}
.muted{opacity:.75;margin-top:10px;line-height:1.35}
code{background:#0b1220;padding:2px 6px;border-radius:8px}
.row{margin-top:10px; word-break:break-all;}
</style>
</head>
<body>
<div class="card">
  <h2 style="margin:0 0 8px 0;">Смяна на парола</h2>
  <div class="muted">Натисни бутона, за да отвориш AutoHelp и да смениш паролата.</div>

  <a class="btn" href="${appLink}">Open AutoHelp</a>
  ${expoGoLink ? `<a class="btn" style="margin-left:10px" href="${expoGoLink}">Open in Expo Go</a>` : ""}

  <div class="row muted">Ако си на компютър — отвори имейла на телефона.</div>
  <div class="row muted">App deep link: <code>${appLink}</code></div>
  ${expoGoLink ? `<div class="row muted">Expo Go link: <code>${expoGoLink}</code></div>` : ""}
</div>

<script nonce="${nonce}">
setTimeout(() => { window.location.href = "${appLink}"; }, 200);
${expoGoLink ? `setTimeout(() => { window.location.href = "${expoGoLink}"; }, 900);` : ""}
</script>
</body>
</html>`);
});

// ======================
// AUTH
// ======================
// Strict validation for the optional car_reg_month/car_reg_year fields on
// registration ONLY. Deliberately NOT reused by/shared with the vehicle
// POST/PUT endpoints (their existing inline checks have known quirks --
// truthy-check treats 0 as empty, no Number.isInteger check lets decimals
// and NaN through -- left untouched as a separate, already-tracked matter).
// Both fields stay independently optional here (no "both or neither" rule,
// preserving current product semantics): empty/null/undefined -> null;
// if provided, must be a finite integer within range, otherwise the whole
// request is rejected with 400 before any DB write is attempted.
function parseStrictRegDate(monthRaw, yearRaw) {
  const isEmpty = (v) => v === null || v === undefined || v === "";
  const isNumericInput = (v) => typeof v === "number" || typeof v === "string";

  let month = null;
  if (!isEmpty(monthRaw)) {
    if (!isNumericInput(monthRaw)) return { error: "INVALID_MONTH" };
    const n = Number(monthRaw);
    if (!Number.isInteger(n) || n < 1 || n > 12) return { error: "INVALID_MONTH" };
    month = n;
  }

  let year = null;
  if (!isEmpty(yearRaw)) {
    if (!isNumericInput(yearRaw)) return { error: "INVALID_YEAR" };
    const n = Number(yearRaw);
    if (!Number.isInteger(n) || n < 1900 || n > new Date().getFullYear()) return { error: "INVALID_YEAR" };
    year = n;
  }

  return { month, year };
}

app.post("/api/auth/register-user", rlRegister, (req, res) => {
  const { firstName = "", lastName = "", username = "", email = "", password = "",
          car_make, car_model, car_reg_month, car_reg_year,
          car_pickerl_month, car_pickerl_year } = req.body || {};
  const e = normalizeEmail(email);
  const u = String(username).trim();
  const fn = String(firstName).trim();
  const ln = String(lastName).trim();

  if (!fn || !ln || !u || !e || String(password).length < 6) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }
  if (!isValidEmail(e)) return res.status(400).json({ ok: false, error: "INVALID_EMAIL" });

  const carPickerl = parsePickerlFields(car_pickerl_month, car_pickerl_year);
  if (carPickerl.error) return res.status(400).json({ ok: false, error: carPickerl.error });

  const carReg = parseStrictRegDate(car_reg_month, car_reg_year);
  if (carReg.error) return res.status(400).json({ ok: false, error: carReg.error });

  const exists =
    db.prepare("SELECT 1 FROM users WHERE email = ?").get(e) ||
    db.prepare("SELECT 1 FROM companies WHERE email = ?").get(e);

  if (exists) return res.status(409).json({ ok: false, error: "EMAIL_EXISTS" });

  const id = createId("u");
  const passwordHash = bcrypt.hashSync(String(password), 10);
  const createdAt = nowMs();

  db.prepare(
    "INSERT INTO users (id, email, username, firstName, lastName, passwordHash, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(id, e, u, fn, ln, passwordHash, createdAt);

  // Optional vehicle — create only if at least one field is provided
  const carMake = String(car_make || "").trim();
  const carModel = String(car_model || "").trim();
  if (carMake || carModel || carReg.month || carReg.year || carPickerl.month || carPickerl.year) {
    db.prepare(
      "INSERT INTO vehicles (user_id, make, model, reg_month, reg_year, pickerl_month, pickerl_year) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).run(id, carMake || null, carModel || null, carReg.month, carReg.year, carPickerl.month, carPickerl.year);
  }

  const token = signToken({ type: "user", userId: id });

  return res.json({ ok: true, token, user: { id, email: e, username: u, firstName: fn, lastName: ln, createdAt } });
});

app.post("/api/auth/login-user", rlLogin, (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (!password || (!email && !username)) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  const row = email
    ? db.prepare("SELECT * FROM users WHERE email = ?").get(email)
    : db.prepare("SELECT * FROM users WHERE username = ?").get(username);

  // One counter per real account (e-mail and username share it).
  const accountKey = row ? `user:id:${row.id}` : email ? `user:email:${email}` : `user:name:${username.toLowerCase()}`;
  if (!checkLoginPassword(res, accountKey, row, password)) return;

  const token = signToken({ type: "user", userId: row.id });

  return res.json({
    ok: true,
    token,
    user: {
      id: row.id,
      email: row.email,
      username: row.username,
      firstName: row.firstName,
      lastName: row.lastName,
      createdAt: row.createdAt,
    },
  });
});

// Register company
app.post("/api/auth/register-company", rlRegister, (req, res) => {
  const {
    companyName = "",
    phone = "",
    address = "",
    email = "",
    password = "",
    categories = [],
    lat = null,
    lng = null,
    workingHoursJson = null,
  } = req.body || {};

  const e = normalizeEmail(email);
  const normalizedCategories = normalizeCategoriesArray(categories);

  if (
    !String(companyName).trim() ||
    !String(phone).trim() ||
    !String(address).trim() ||
    !e ||
    String(password).length < 6 ||
    normalizedCategories.length === 0
  ) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }
  if (!isValidEmail(e)) return res.status(400).json({ ok: false, error: "INVALID_EMAIL" });

  // New companies must register with a full international (E.164) phone number.
  const phoneE164 = normalizePhoneInput(phone);
  if (!isE164Phone(phoneE164)) {
    return res.status(400).json({ ok: false, error: "PHONE_INVALID" });
  }

  const exists =
    db.prepare("SELECT 1 FROM users WHERE email = ?").get(e) ||
    db.prepare("SELECT 1 FROM companies WHERE email = ?").get(e);

  if (exists) return res.status(409).json({ ok: false, error: "EMAIL_EXISTS" });

  // Only hours the company really entered. The registration form of the
  // installed apps sends no hours of its own, just the form's 09:00–18:00
  // defaults as `openingHours`; those are deliberately ignored, so a new
  // company's hours stay unknown until it sets them in the dashboard.
  const hoursToStore = normalizeWorkingHoursInput(workingHoursJson);
  if (hoursToStore === undefined) return res.status(400).json({ ok: false, error: "INVALID_WORKING_HOURS" });

  const servicesTextRaw = req.body?.servicesText;
  const servicesText = typeof servicesTextRaw === "string" ? servicesTextRaw.trim() : "";

  const id = createId("c");
  const passwordHash = bcrypt.hashSync(String(password), 10);
  const createdAt = nowMs();

  const coords = parseCoordPair(lat, lng);
  const latNum = coords ? coords.lat : null;
  const lngNum = coords ? coords.lng : null;

  const cols = ["id", "email", "companyName", "phone", "address", "passwordHash", "categoriesJson", "createdAt"];
  const vals = [
    id,
    e,
    String(companyName).trim(),
    phoneE164,
    String(address).trim(),
    passwordHash,
    JSON.stringify(normalizedCategories),
    createdAt,
  ];

  if (hasColumn("companies", "lat")) {
    cols.push("lat");
    vals.push(Number.isFinite(latNum) ? latNum : null);
  }
  if (hasColumn("companies", "lng")) {
    cols.push("lng");
    vals.push(Number.isFinite(lngNum) ? lngNum : null);
  }
  if (hasColumn("companies", "workingHoursJson")) {
    cols.push("workingHoursJson");
    vals.push(hoursToStore);
  }

  if (hasColumn("companies", "servicesText")) {
    cols.push("servicesText");
    vals.push(servicesText);
  }

  const placeholders = cols.map(() => "?").join(", ");
  db.prepare(`INSERT INTO companies (${cols.join(", ")}) VALUES (${placeholders})`).run(...vals);

  const token = signToken({ type: "company", companyId: id });

  return res.json({
    ok: true,
    token,
    company: {
      id,
      email: e,
      companyName: String(companyName).trim(),
      phone: phoneE164,
      address: String(address).trim(),
      categories: normalizedCategories,
      lat: Number.isFinite(latNum) ? latNum : null,
      lng: Number.isFinite(lngNum) ? lngNum : null,
      createdAt,
      servicesText,
    },
  });
});

app.post("/api/auth/login-company", rlLogin, (req, res) => {
  const identifier = String(req.body?.email || "").trim();
  const password = String(req.body?.password || "");
  if (!identifier || !password) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  let row;
  if (identifier.includes("@")) {
    row = db.prepare("SELECT * FROM companies WHERE email = ?").get(identifier.toLowerCase());
  } else {
    const rows = db.prepare("SELECT * FROM companies WHERE companyName = ?").all(identifier);
    row = rows.length === 1 ? rows[0] : null;
  }

  // One counter per real account (e-mail and company name share it).
  const accountKey = row ? `company:id:${row.id}` : `company:${identifier.toLowerCase()}`;
  if (!checkLoginPassword(res, accountKey, row, password)) return;

  const token = signToken({ type: "company", companyId: row.id });

  return res.json({
    ok: true,
    token,
    company: {
      id: row.id,
      email: row.email,
      companyName: row.companyName,
      phone: row.phone,
      address: row.address,
      categories: parseCategories(row.categoriesJson),
      lat: row.lat ?? null,
      lng: row.lng ?? null,
      workingHoursJson: row.workingHoursJson ?? null,
      logoUrl: row.logoUrl ?? null,
      images: parseImages(row.imagesJson),
      // ✅ NEW
      servicesText: typeof row.servicesText === "string" ? row.servicesText : "",
      createdAt: row.createdAt,
    },
  });
});

// Update profile
app.post("/api/company/update-profile", requireCompanyAuth, (req, res) => {
  const companyId = req.company.companyId;

  const lat = req.body?.lat;
  const lng = req.body?.lng;
  const workingHoursJson = req.body?.workingHoursJson;

  const servicesTextRaw = req.body?.servicesText;
  const servicesText = typeof servicesTextRaw === "string" ? servicesTextRaw : undefined;

  const logoUrlRaw = req.body?.logoUrl;
  const logoUrl = typeof logoUrlRaw === "string" ? logoUrlRaw : undefined;

  const imagesJsonRaw = req.body?.imagesJson;
  const imagesJson = typeof imagesJsonRaw === "string" ? imagesJsonRaw : undefined;

  const companyNameRaw = req.body?.companyName;
  const companyName = typeof companyNameRaw === "string" && companyNameRaw.trim() ? companyNameRaw.trim() : undefined;

  const phoneRaw = req.body?.phone;
  const phone = typeof phoneRaw === "string" && phoneRaw.trim() ? phoneRaw.trim() : undefined;

  const addressRaw = req.body?.address;
  const address = typeof addressRaw === "string" && addressRaw.trim() ? addressRaw.trim() : undefined;

  const emailRaw = req.body?.email;
  const emailNew = typeof emailRaw === "string" && emailRaw.trim() ? normalizeEmail(emailRaw) : undefined;

  // Check email uniqueness only if email is being changed
  if (emailNew !== undefined) {
    const current = db.prepare("SELECT email FROM companies WHERE id = ?").get(companyId);
    // Only a changed address must be valid: the dashboard always sends the
    // stored one along, and an older (non-conforming) one must not block saves.
    if (current && normalizeEmail(current.email) !== emailNew) {
      if (!isValidEmail(emailNew)) return res.status(400).json({ ok: false, error: "INVALID_EMAIL" });
      const taken =
        db.prepare("SELECT 1 FROM companies WHERE email = ? AND id != ?").get(emailNew, companyId) ||
        db.prepare("SELECT 1 FROM users WHERE email = ?").get(emailNew);
      if (taken) return res.status(409).json({ ok: false, error: "EMAIL_EXISTS" });
    }
  }

  // Phone is validated only when it actually changes: an existing company whose
  // stored number is legacy (non-international) can keep saving other fields,
  // and its number is never rewritten until it edits the phone itself.
  let phoneToStore;
  if (phone !== undefined) {
    const current = db.prepare("SELECT phone FROM companies WHERE id = ?").get(companyId);
    if (!current || phone !== String(current.phone || "").trim()) {
      const phoneE164 = normalizePhoneInput(phone);
      if (!isE164Phone(phoneE164)) {
        return res.status(400).json({ ok: false, error: "PHONE_INVALID" });
      }
      phoneToStore = phoneE164;
    }
  }

  // Coordinates are only ever replaced by a complete, valid pair. Empty,
  // partial or invalid values (e.g. the dashboard's empty fields after its
  // data failed to load) keep the stored position, so a company can't vanish
  // from the radius search by saving its profile.
  const coords = parseCoordPair(lat, lng);

  let hoursToStore;
  if (workingHoursJson !== undefined) {
    hoursToStore = normalizeWorkingHoursInput(workingHoursJson);
    if (hoursToStore === undefined) return res.status(400).json({ ok: false, error: "INVALID_WORKING_HOURS" });
  }

  const sets = [];
  const vals = [];

  if (coords && hasColumn("companies", "lat") && hasColumn("companies", "lng")) {
    sets.push("lat = ?", "lng = ?");
    vals.push(coords.lat, coords.lng);
  }
  if (hasColumn("companies", "workingHoursJson") && workingHoursJson !== undefined) {
    sets.push("workingHoursJson = ?");
    vals.push(hoursToStore);
  }

  // ✅ NEW: save servicesText
  if (hasColumn("companies", "servicesText") && servicesText !== undefined) {
    sets.push("servicesText = ?");
    vals.push(String(servicesText));
  }

  if (hasColumn("companies", "logoUrl") && logoUrl !== undefined) {
    sets.push("logoUrl = ?");
    vals.push(String(logoUrl));
  }
  if (hasColumn("companies", "imagesJson") && imagesJson !== undefined) {
    sets.push("imagesJson = ?");
    vals.push(String(imagesJson));
  }

  if (companyName !== undefined) {
    sets.push("companyName = ?");
    vals.push(companyName);
  }
  if (phoneToStore !== undefined) {
    sets.push("phone = ?");
    vals.push(phoneToStore);
  }
  if (address !== undefined) {
    sets.push("address = ?");
    vals.push(address);
  }
  if (emailNew !== undefined) {
    sets.push("email = ?");
    vals.push(emailNew);
  }

  // Nothing to change (e.g. only empty coordinates): a no-op success, as the
  // endpoint always answered before coordinates became optional here.
  if (!sets.length) return res.json({ ok: true });

  vals.push(companyId);
  db.prepare(`UPDATE companies SET ${sets.join(", ")} WHERE id = ?`).run(...vals);

  return res.json({ ok: true });
});

// Forgot/reset helpers
function findAccountByEmail(email) {
  const e = normalizeEmail(email);
  const u = db.prepare("SELECT id, email FROM users WHERE email = ?").get(e);
  if (u) return { type: "user", id: u.id, email: u.email };
  const c = db.prepare("SELECT id, email FROM companies WHERE email = ?").get(e);
  if (c) return { type: "company", id: c.id, email: c.email };
  return null;
}
function updatePasswordByAccount(type, id, newPassword) {
  const passwordHash = bcrypt.hashSync(String(newPassword), 10);
  if (type === "user") {
    db.prepare("UPDATE users SET passwordHash = ? WHERE id = ?").run(passwordHash, id);
    return true;
  }
  if (type === "company") {
    db.prepare("UPDATE companies SET passwordHash = ? WHERE id = ?").run(passwordHash, id);
    return true;
  }
  return false;
}

app.post("/api/auth/forgot-password", rlForgot, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const lang = String(req.body?.lang || "en");
  const genericOk = { ok: true, message: msg(lang, "genericSent") };

  // A malformed address never reaches the mail library; the answer is the
  // same generic one, so it reveals nothing.
  if (!email || !isValidEmail(email)) return res.json(genericOk);

  // At most 3 reset e-mails per address per hour, whatever IP asks. The
  // answer stays the same generic one, so it reveals nothing about the account.
  if (resetMailsPerEmail.isBlocked(email)) return res.json(genericOk);

  const acc = findAccountByEmail(email);
  if (!acc) return res.json(genericOk);

  if (!hasSmtp()) return res.json(genericOk);
  resetMailsPerEmail.hit(email);

  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = sha256Hex(rawToken);
  const createdAt = nowMs();
  const expiresAt = createdAt + RESET_TOKEN_TTL_MS;

  db.prepare("DELETE FROM password_resets WHERE accountType = ? AND accountId = ?").run(acc.type, acc.id);
  db.prepare(
    "INSERT INTO password_resets (tokenHash, accountType, accountId, expiresAt, createdAt) VALUES (?, ?, ?, ?, ?)"
  ).run(tokenHash, acc.type, acc.id, expiresAt, createdAt);

  const publicBase = getPublicBaseUrl(req);
  const resetLink = `${publicBase}/reset-password?token=${encodeURIComponent(rawToken)}`;

  // Answer first, send afterwards: waiting for SMTP only for existing
  // accounts would reveal through the response time that the account exists.
  res.json(genericOk);

  try {
    const transporter = getTransporter();
    await transporter.verify();
    await transporter.sendMail({
      from: SMTP_FROM,
      to: email,
      subject: msg(lang, "subject"),
      text: msg(lang, "emailText")(resetLink),
    });
  } catch (e) {
    console.log("❌ sendMail ERROR:", e?.message || e);
  }
});

app.post("/api/auth/reset-password", rlReset, (req, res) => {
  const token = String(req.body?.token || "").trim();
  const newPassword = String(req.body?.newPassword || "");

  if (!token || newPassword.length < 6) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }

  const tokenHash = sha256Hex(token);
  const row = db.prepare("SELECT * FROM password_resets WHERE tokenHash = ?").get(tokenHash);

  if (!row) return res.status(400).json({ ok: false, error: "TOKEN_INVALID" });

  if (nowMs() > Number(row.expiresAt || 0)) {
    db.prepare("DELETE FROM password_resets WHERE tokenHash = ?").run(tokenHash);
    return res.status(400).json({ ok: false, error: "TOKEN_EXPIRED" });
  }

  const changed = updatePasswordByAccount(row.accountType, row.accountId, newPassword);
  db.prepare("DELETE FROM password_resets WHERE tokenHash = ?").run(tokenHash);

  if (!changed) return res.status(400).json({ ok: false, error: "ACCOUNT_NOT_FOUND" });

  return res.json({ ok: true });
});

// ======================
// DELETE ACCOUNT
// ======================
app.delete("/api/auth/delete-user", requireUserAuth, (req, res) => {
  const userId = req.user.userId;

  const deleteAccount = db.transaction(() => {
    db.prepare("DELETE FROM password_resets WHERE accountType = 'user' AND accountId = ?").run(userId);
    db.prepare("DELETE FROM ratings WHERE userId = ?").run(userId);
    db.prepare("DELETE FROM vehicles WHERE user_id = ?").run(userId);
    db.prepare("DELETE FROM users WHERE id = ?").run(userId);
  });

  try {
    deleteAccount();
    return res.json({ ok: true });
  } catch (e) {
    console.error("delete-user error:", e?.message || e);
    return res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

app.delete("/api/auth/delete-company", requireCompanyAuth, (req, res) => {
  const companyId = req.company.companyId;

  const deleteAccount = db.transaction(() => {
    db.prepare("DELETE FROM password_resets WHERE accountType = 'company' AND accountId = ?").run(companyId);
    db.prepare("DELETE FROM ratings WHERE serviceId = ?").run(companyId);
    db.prepare("DELETE FROM companies WHERE id = ?").run(companyId);
  });

  try {
    deleteAccount();
    return res.json({ ok: true });
  } catch (e) {
    console.error("delete-company error:", e?.message || e);
    return res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

// ======================
// ✅ COMPANIES LIST
// GET /api/companies?category=inspection&page=1&limit=20&lat=48.2&lng=16.3&radiusKm=30
// ======================
app.get("/api/companies", (req, res) => {
  const categoryRaw = req.query.category ? String(req.query.category) : "";
  const category = categoryRaw ? normalizeCategoryId(categoryRaw) : "";

  const page  = Math.max(1, parseInt(req.query.page)  || 1);
  const limit = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));

  // Radius params — optional. If not provided, behaviour is identical to before.
  const userLat   = req.query.lat      ? Number(req.query.lat)      : null;
  const userLng   = req.query.lng      ? Number(req.query.lng)      : null;
  const radiusKm  = req.query.radiusKm ? Number(req.query.radiusKm) : null;
  const hasUserPos = Number.isFinite(userLat) && Number.isFinite(userLng);
  const useRadius  = hasUserPos && Number.isFinite(radiusKm) && radiusKm > 0;

  const rows = db.prepare(`SELECT * FROM companies`).all();

  const items = [];
  for (const c of rows) {
    const cats = parseCategories(c.categoriesJson);
    if (category && !cats.includes(category)) continue;

    const companyLat = typeof c.lat === "number" ? c.lat : null;
    const companyLng = typeof c.lng === "number" ? c.lng : null;
    const hasCoords  = companyLat !== null && companyLng !== null;

    // Radius mode: companies without coordinates are excluded
    if (useRadius && !hasCoords) continue;

    // Calculate distance if user position is known
    let distanceKm = null;
    if (hasUserPos && hasCoords) {
      distanceKm = haversineKm(userLat, userLng, companyLat, companyLng);
    }

    // Radius filter: exclude companies beyond the selected radius
    if (useRadius && distanceKm > radiusKm) continue;

    const openNow = isOpenNow(c.workingHoursJson);
    const rating  = getRatingStatsByCompanyId(c.id);

    items.push({
      id: c.id,
      email: c.email,
      companyName: c.companyName,
      phone: c.phone,
      address: c.address,
      categories: cats,
      lat: companyLat,
      lng: companyLng,
      openNow,
      distanceKm,
      rating,
      logoUrl: c.logoUrl ?? null,
      images: parseImages(c.imagesJson),
      servicesText: typeof c.servicesText === "string" ? c.servicesText : "",
      createdAt: c.createdAt,
    });
  }

  items.sort((a, b) => {
    // 1. Open first
    const aOpen = a.openNow === true ? 1 : 0;
    const bOpen = b.openNow === true ? 1 : 0;
    if (aOpen !== bOpen) return bOpen - aOpen;

    // 2. Distance (only when user position is known)
    if (hasUserPos) {
      const ad = typeof a.distanceKm === "number" ? a.distanceKm : Infinity;
      const bd = typeof b.distanceKm === "number" ? b.distanceKm : Infinity;
      if (ad !== bd) return ad - bd;
    }

    // 3. Rating
    if (a.rating.average !== b.rating.average) return b.rating.average - a.rating.average;
    if (a.rating.votes   !== b.rating.votes)   return b.rating.votes   - a.rating.votes;

    return Number(b.createdAt || 0) - Number(a.createdAt || 0);
  });

  const total      = items.length;
  const totalPages = Math.ceil(total / limit);
  const paginated  = items.slice((page - 1) * limit, page * limit);

  return res.json({
    ok: true,
    items: paginated,
    category,
    page,
    limit,
    total,
    totalPages,
    hasMore: page < totalPages,
    radiusKm: useRadius ? radiusKm : null,
  });
});

// ======================
// ✅ NEARBY
// ======================
app.get("/api/companies/nearby", (req, res) => {
  const lat = Number(req.query.lat);
  const lng = Number(req.query.lng);
  const radiusKm = req.query.radiusKm ? Number(req.query.radiusKm) : DEFAULT_RADIUS_KM;
  const categoryRaw = req.query.category ? String(req.query.category) : "";
  const category = categoryRaw ? normalizeCategoryId(categoryRaw) : "";

  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }

  const rows = db.prepare(`
    SELECT
      c.*,
      COALESCE(r.avgRating, 0) as avgRating,
      COALESCE(r.votes, 0) as votes
    FROM companies c
    LEFT JOIN (
      SELECT serviceId, AVG(value) as avgRating, COUNT(*) as votes
      FROM ratings
      GROUP BY serviceId
    ) r ON r.serviceId = c.id
    WHERE c.lat IS NOT NULL AND c.lng IS NOT NULL
  `).all();

  const out = [];
  for (const c of rows) {
    const d = haversineKm(lat, lng, Number(c.lat), Number(c.lng));
    if (Number.isFinite(radiusKm) && d > radiusKm) continue;

    const cats = parseCategories(c.categoriesJson);
    if (category && !cats.includes(category)) continue;

    const openNow = isOpenNow(c.workingHoursJson);

    out.push({
      id: c.id,
      email: c.email,
      companyName: c.companyName,
      phone: c.phone,
      address: c.address,
      categories: cats,
      lat: Number(c.lat),
      lng: Number(c.lng),
      distanceKm: Number(d.toFixed(2)),
      openNow,
      rating: {
        average: Number(Number(c.avgRating || 0).toFixed(2)),
        votes: Number(c.votes || 0),
      },
      logoUrl: c.logoUrl ?? null,
      images: parseImages(c.imagesJson),
      // ✅ NEW
      servicesText: typeof c.servicesText === "string" ? c.servicesText : "",
    });
  }

  out.sort((a, b) => {
    const aOpen = a.openNow === true ? 1 : 0;
    const bOpen = b.openNow === true ? 1 : 0;
    if (aOpen !== bOpen) return bOpen - aOpen;
    if (a.distanceKm !== b.distanceKm) return a.distanceKm - b.distanceKm;
    if (a.rating.average !== b.rating.average) return b.rating.average - a.rating.average;
    return b.rating.votes - a.rating.votes;
  });

  return res.json({ ok: true, items: out, category });
});

// ======================
// ✅ NEAREST (single true-closest company, no radius cutoff, no open/rating bias)
// Used exclusively by Home's "Find nearest" button. Registered before
// /api/companies/:id so Express doesn't match "nearest" as an :id value.
// ======================
app.get("/api/companies/nearest", (req, res) => {
  const lat = Number(req.query.lat);
  const lng = Number(req.query.lng);

  if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }

  const rows = db.prepare(`SELECT * FROM companies WHERE lat IS NOT NULL AND lng IS NOT NULL`).all();

  let nearest = null;
  let nearestDist = Infinity;

  for (const c of rows) {
    const d = haversineKm(lat, lng, Number(c.lat), Number(c.lng));
    if (d < nearestDist) {
      nearestDist = d;
      nearest = c;
    }
  }

  if (!nearest) {
    return res.json({ ok: true, item: null });
  }

  const rating = getRatingStatsByCompanyId(nearest.id);

  return res.json({
    ok: true,
    item: {
      id: nearest.id,
      email: nearest.email,
      companyName: nearest.companyName,
      phone: nearest.phone,
      address: nearest.address,
      categories: parseCategories(nearest.categoriesJson),
      lat: Number(nearest.lat),
      lng: Number(nearest.lng),
      distanceKm: Number(nearestDist.toFixed(2)),
      openNow: isOpenNow(nearest.workingHoursJson),
      rating,
      logoUrl: nearest.logoUrl ?? null,
      images: parseImages(nearest.imagesJson),
      servicesText: typeof nearest.servicesText === "string" ? nearest.servicesText : "",
    },
  });
});

// ======================
// GEOCODING (address -> suggested position)
// ======================
// GET /api/geocode?q=<address>&lang=de
// Only ever a SUGGESTION: the app shows it on a map and the company must
// confirm (and may move) the pin; nothing is stored here.
//
// Provider: GEOCODER_PROVIDER = "nominatim" | "none" (default "none": the
// public OpenStreetMap service is only used once it has been switched on
// deliberately — see its usage policy). Its rules are kept server-side for
// all users together: one request per explicit click (no autocomplete), at
// most 1 request per second in total, an identifying User-Agent, results
// cached, and a per-IP limit against misuse of this public endpoint.
const GEOCODER_PROVIDER = String(process.env.GEOCODER_PROVIDER || "none").trim().toLowerCase();
const NOMINATIM_URL = String(process.env.NOMINATIM_URL || "https://nominatim.openstreetmap.org").replace(/\/+$/, "");
const GEOCODER_TIMEOUT_MS = Number(process.env.GEOCODER_TIMEOUT_MS || 6000);
const GEOCODER_USER_AGENT = `AutoHelp-Server/1.0 (+${FIXED_PUBLIC_BASE_URL || "https://autohelp-server.onrender.com"})`;
const GEOCODE_MIN_INTERVAL_MS = 1100;
const GEOCODE_MAX_WAITING = 5;
const GEOCODE_CACHE_MAX = 2000;
const GEOCODE_CACHE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const GEOCODE_EMPTY_TTL_MS = 24 * 60 * 60 * 1000;

const rlGeocode = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20, keyPrefix: "geocode" });
const geocodeCache = new Map(); // key -> { at, ttl, results }
let geocodeQueue = Promise.resolve();
let geocodeWaiting = 0;
let geocodeLastCallAt = 0;

// Nominatim place_rank: 30 = building / house number, 26–29 = street, lower = area or city.
function geocodePrecision(placeRank) {
  const r = Number(placeRank);
  if (r >= 30) return "exact";
  if (r >= 26) return "street";
  return "area";
}

async function callNominatim(q, lang) {
  const url =
    `${NOMINATIM_URL}/search?format=jsonv2&addressdetails=0&limit=3&q=${encodeURIComponent(q)}` +
    (process.env.GEOCODER_EMAIL ? `&email=${encodeURIComponent(process.env.GEOCODER_EMAIL)}` : "");
  const resp = await fetch(url, {
    headers: { "User-Agent": GEOCODER_USER_AGENT, "Accept-Language": lang || "en" },
    signal: AbortSignal.timeout(GEOCODER_TIMEOUT_MS),
  });
  if (!resp.ok) throw new Error(`GEOCODER_HTTP_${resp.status}`);
  const list = await resp.json();
  if (!Array.isArray(list)) throw new Error("GEOCODER_BAD_RESPONSE");
  return list
    .map((r) => ({ coords: parseCoordPair(r.lat, r.lon), label: String(r.display_name || ""), precision: geocodePrecision(r.place_rank) }))
    .filter((r) => r.coords)
    .map((r) => ({ lat: r.coords.lat, lng: r.coords.lng, label: r.label.slice(0, 300), precision: r.precision }));
}

// One provider call at a time, at least GEOCODE_MIN_INTERVAL_MS apart.
function queuedGeocode(q, lang) {
  if (geocodeWaiting >= GEOCODE_MAX_WAITING) return Promise.reject(httpError(503, "GEOCODER_BUSY"));
  geocodeWaiting++;
  const run = geocodeQueue.then(async () => {
    const wait = geocodeLastCallAt + GEOCODE_MIN_INTERVAL_MS - Date.now();
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    try {
      return await callNominatim(q, lang);
    } finally {
      geocodeLastCallAt = Date.now();
      geocodeWaiting--;
    }
  });
  geocodeQueue = run.catch(() => {});
  return run;
}

app.get("/api/geocode", rlGeocode, async (req, res) => {
  const q = String(req.query.q || "").replace(/\s+/g, " ").trim();
  const lang = /^[a-z]{2}$/i.test(String(req.query.lang || "")) ? String(req.query.lang).toLowerCase() : "en";
  if (q.length < 5 || q.length > 300 || /[\u0000-\u001f]/.test(q)) {
    return res.status(400).json({ ok: false, error: "INVALID_ADDRESS" });
  }
  if (GEOCODER_PROVIDER !== "nominatim") return res.status(503).json({ ok: false, error: "GEOCODER_UNAVAILABLE" });

  const key = `${lang}|${q.toLowerCase()}`;
  const cached = geocodeCache.get(key);
  if (cached && Date.now() - cached.at < cached.ttl) return res.json({ ok: true, results: cached.results, cached: true });

  try {
    const results = await queuedGeocode(q, lang);
    if (geocodeCache.size >= GEOCODE_CACHE_MAX) geocodeCache.delete(geocodeCache.keys().next().value);
    geocodeCache.set(key, { at: Date.now(), ttl: results.length ? GEOCODE_CACHE_TTL_MS : GEOCODE_EMPTY_TTL_MS, results });
    return res.json({ ok: true, results });
  } catch (e) {
    if (e?.code === "GEOCODER_BUSY") return res.status(503).json({ ok: false, error: "GEOCODER_BUSY" });
    console.error("geocode error:", e?.message || e);
    return res.status(502).json({ ok: false, error: "GEOCODER_ERROR" });
  }
});

// Company details
app.get("/api/companies/:id", (req, res) => {
  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  const c = db.prepare("SELECT * FROM companies WHERE id = ?").get(id);
  if (!c) return res.status(404).json({ ok: false, error: "NOT_FOUND" });

  const cats = parseCategories(c.categoriesJson);
  const openNow = isOpenNow(c.workingHoursJson);
  const rating = getRatingStatsByCompanyId(c.id);

  return res.json({
    ok: true,
    item: {
      id: c.id,
      email: c.email,
      companyName: c.companyName,
      phone: c.phone,
      address: c.address,
      categories: cats,
      lat: c.lat ?? null,
      lng: c.lng ?? null,
      workingHoursJson: c.workingHoursJson ?? null,
      openNow,
      rating,
      logoUrl: c.logoUrl ?? null,
      images: parseImages(c.imagesJson),
      // ✅ NEW
      servicesText: typeof c.servicesText === "string" ? c.servicesText : "",
      createdAt: c.createdAt,
    },
  });
});

// Ratings
app.post("/api/ratings", requireUserAuth, (req, res) => {
  const userId = req.user.userId;
  const serviceId = String(req.body?.serviceId || "").trim();
  const value = Number(req.body?.value);

  if (!serviceId || !Number.isInteger(value) || value < 1 || value > 5) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }
  if (!db.prepare("SELECT 1 FROM companies WHERE id = ?").get(serviceId)) {
    return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  }

  // Kept as before for the installed apps: a second vote is refused (409).
  // Changing a rating is PUT /api/ratings/:serviceId.
  const existing = db.prepare("SELECT id FROM ratings WHERE userId = ? AND serviceId = ?").get(userId, serviceId);
  if (existing) return res.status(409).json({ ok: false, error: "ALREADY_VOTED" });

  const id = createId("r");
  const createdAt = nowMs();

  try {
    db.prepare("INSERT INTO ratings (id, userId, serviceId, value, createdAt) VALUES (?, ?, ?, ?, ?)").run(
      id,
      userId,
      serviceId,
      value,
      createdAt
    );
  } catch (e) {
    if (String(e?.message || "").toLowerCase().includes("unique")) {
      return res.status(409).json({ ok: false, error: "ALREADY_VOTED" });
    }
    console.error("ratings insert error:", e);
    return res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }

  const stats = db.prepare("SELECT AVG(value) as avg, COUNT(*) as votes FROM ratings WHERE serviceId = ?").get(serviceId);

  return res.status(201).json({
    ok: true,
    rating: { id, serviceId, value, createdAt },
    stats: { average: Number(stats?.avg || 0), votes: Number(stats?.votes || 0) },
  });
});

function ratingStats(serviceId) {
  const stats = db.prepare("SELECT AVG(value) as avg, COUNT(*) as votes FROM ratings WHERE serviceId = ?").get(serviceId);
  return { average: Number(stats?.avg || 0), votes: Number(stats?.votes || 0) };
}

// GET /api/ratings/mine/:serviceId — the logged-in user's own rating of a company (or null)
app.get("/api/ratings/mine/:serviceId", requireUserAuth, (req, res) => {
  const serviceId = String(req.params.serviceId || "").trim();
  const row = db
    .prepare("SELECT id, serviceId, value, createdAt FROM ratings WHERE userId = ? AND serviceId = ?")
    .get(req.user.userId, serviceId);
  return res.json({ ok: true, serviceId, rating: row || null });
});

// PUT /api/ratings/:serviceId — set or change the user's own rating (1–5)
app.put("/api/ratings/:serviceId", requireUserAuth, (req, res) => {
  const userId = req.user.userId;
  const serviceId = String(req.params.serviceId || "").trim();
  const value = Number(req.body?.value);

  if (!Number.isInteger(value) || value < 1 || value > 5) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }
  if (!db.prepare("SELECT 1 FROM companies WHERE id = ?").get(serviceId)) {
    return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  }

  // One row per user and company: change the existing rating or add it. Done
  // in one synchronous transaction, so parallel requests can't duplicate it
  // (and it doesn't depend on the table's UNIQUE constraint being present).
  db.transaction(() => {
    const changed = db.prepare("UPDATE ratings SET value = ? WHERE userId = ? AND serviceId = ?").run(value, userId, serviceId);
    if (changed.changes === 0) {
      db.prepare("INSERT INTO ratings (id, userId, serviceId, value, createdAt) VALUES (?, ?, ?, ?, ?)").run(
        createId("r"),
        userId,
        serviceId,
        value,
        nowMs()
      );
    }
  })();

  const rating = db
    .prepare("SELECT id, serviceId, value, createdAt FROM ratings WHERE userId = ? AND serviceId = ?")
    .get(userId, serviceId);
  return res.json({ ok: true, rating, stats: ratingStats(serviceId) });
});

app.get("/api/ratings/stats/:serviceId", (req, res) => {
  const serviceId = String(req.params.serviceId || "").trim();
  if (!serviceId) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  const stats = db.prepare("SELECT AVG(value) as avg, COUNT(*) as votes FROM ratings WHERE serviceId = ?").get(serviceId);
  const company = db.prepare("SELECT viewCount, callCount FROM companies WHERE id = ?").get(serviceId);

  return res.json({
    ok: true,
    serviceId,
    average: Number(stats?.avg || 0),
    votes: Number(stats?.votes || 0),
    views: Number(company?.viewCount || 0),
    calls: Number(company?.callCount || 0),
  });
});

// ✅ Track profile view (called from ServiceDetail on open)
app.post("/api/companies/:id/view", (req, res) => {
  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  const company = db.prepare("SELECT id FROM companies WHERE id = ?").get(id);
  if (!company) return res.status(404).json({ ok: false, error: "NOT_FOUND" });

  db.prepare("UPDATE companies SET viewCount = COALESCE(viewCount, 0) + 1 WHERE id = ?").run(id);
  const updated = db.prepare("SELECT viewCount FROM companies WHERE id = ?").get(id);

  return res.json({ ok: true, views: Number(updated?.viewCount || 0) });
});

app.post("/api/companies/:id/call", (req, res) => {
  const id = String(req.params.id || "").trim();
  if (!id) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  const company = db.prepare("SELECT id FROM companies WHERE id = ?").get(id);
  if (!company) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  db.prepare("UPDATE companies SET callCount = COALESCE(callCount, 0) + 1 WHERE id = ?").run(id);
  const updated = db.prepare("SELECT callCount FROM companies WHERE id = ?").get(id);
  return res.json({ ok: true, calls: Number(updated?.callCount || 0) });
});

// ======================
// ✅ DEBUG (dev only)
// ======================
app.get("/api/debug/db", (req, res) => {
  if (IS_PROD) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  const exists = fs.existsSync(DB_FILE);
  let size = null;
  try {
    size = exists ? fs.statSync(DB_FILE).size : null;
  } catch {}

  const users = db.prepare("SELECT COUNT(*) as n FROM users").get().n;
  const companies = db.prepare("SELECT COUNT(*) as n FROM companies").get().n;
  const withLatLng = db.prepare("SELECT COUNT(*) as n FROM companies WHERE lat IS NOT NULL AND lng IS NOT NULL").get().n;
  const ratings = db.prepare("SELECT COUNT(*) as n FROM ratings").get().n;

  const last5 = db
    .prepare("SELECT id, email, companyName, categoriesJson, lat, lng, logoUrl, imagesJson, servicesText, createdAt FROM companies ORDER BY createdAt DESC LIMIT 5")
    .all()
    .map((r) => ({
      ...r,
      categories: parseCategories(r.categoriesJson),
      images: parseImages(r.imagesJson),
      servicesText: typeof r.servicesText === "string" ? r.servicesText : "",
    }));

  res.json({
    ok: true,
    env: NODE_ENV,
    dbFile: DB_FILE,
    dbFileExists: exists,
    dbFileSize: size,
    hasUploads: hasUploads(),
    uploadDir: UPLOAD_DIR,
    users,
    companies,
    withLatLng,
    ratings,
    last5,
  });
});

// ======================
// USER PROFILE & VEHICLES
// ======================

// GET /api/user/me — профил на логнатия потребител
app.get("/api/user/me", requireUserAuth, (req, res) => {
  const user = db.prepare("SELECT id, firstName, lastName, username, email FROM users WHERE id = ?").get(req.user.userId);
  if (!user) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  return res.json({ ok: true, user });
});

// PUT /api/user/me — смяна на имейл
app.put("/api/user/me", requireUserAuth, (req, res) => {
  const email = normalizeEmail(req.body.email || "");
  if (!email) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  const current = db.prepare("SELECT email FROM users WHERE id = ?").get(req.user.userId);
  if (normalizeEmail(current?.email) !== email && !isValidEmail(email)) {
    return res.status(400).json({ ok: false, error: "INVALID_EMAIL" });
  }

  // A company's address too: one e-mail belongs to one account, otherwise a
  // password reset for it would reach the driver and never the company.
  const existing =
    db.prepare("SELECT id FROM users WHERE email = ? AND id != ?").get(email, req.user.userId) ||
    db.prepare("SELECT id FROM companies WHERE email = ?").get(email);
  if (existing) return res.status(409).json({ ok: false, error: "EMAIL_EXISTS" });

  db.prepare("UPDATE users SET email = ? WHERE id = ?").run(email, req.user.userId);
  return res.json({ ok: true });
});

// PUT /api/user/password — смяна на парола
app.put("/api/user/password", requireUserAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  if (String(newPassword).length < 6) return res.status(400).json({ ok: false, error: "PASS_TOO_SHORT" });

  // Own counter, separate from login: failed logins by others don't block a
  // password change, and vice versa.
  const accountKey = `user:${req.user.userId}`;
  const wait = passwordChangeThrottle.retryAfterMs(accountKey);
  if (wait > 0) return sendRateLimited(res, wait);

  const user = db.prepare("SELECT passwordHash FROM users WHERE id = ?").get(req.user.userId);
  if (!user) return res.status(404).json({ ok: false, error: "NOT_FOUND" });

  const match = bcrypt.compareSync(String(currentPassword), user.passwordHash);
  if (!match) {
    passwordChangeThrottle.fail(accountKey);
    return res.status(401).json({ ok: false, error: "WRONG_PASSWORD" });
  }
  passwordChangeThrottle.clear(accountKey);

  const hashed = bcrypt.hashSync(String(newPassword), 10);
  db.prepare("UPDATE users SET passwordHash = ? WHERE id = ?").run(hashed, req.user.userId);
  return res.json({ ok: true });
});

// Pickerl / §57a month+year: both null (no reminder set) or both valid — never just one.
function parsePickerlFields(monthRaw, yearRaw) {
  const isEmpty = (v) => v === null || v === undefined || v === "";
  const month = isEmpty(monthRaw) ? null : Number(monthRaw);
  const year = isEmpty(yearRaw) ? null : Number(yearRaw);

  if (month !== null && (!Number.isInteger(month) || month < 1 || month > 12)) {
    return { error: "INVALID_PICKERL_MONTH" };
  }
  // Pickerl is a forward-looking due date (unlike reg_year, which looks backward),
  // so the upper bound intentionally does NOT reuse reg_year's "<= current year" rule.
  const maxYear = new Date().getFullYear() + 20;
  if (year !== null && (!Number.isInteger(year) || year < 1900 || year > maxYear)) {
    return { error: "INVALID_PICKERL_YEAR" };
  }
  if ((month === null) !== (year === null)) {
    return { error: "INVALID_INPUT" };
  }

  return { month, year };
}

// GET /api/user/vehicles — всички автомобили на потребителя
app.get("/api/user/vehicles", requireUserAuth, (req, res) => {
  const vehicles = db.prepare("SELECT * FROM vehicles WHERE user_id = ? ORDER BY created_at ASC").all(req.user.userId);
  return res.json({ ok: true, vehicles });
});

// POST /api/user/vehicles — добавяне на нов автомобил
app.post("/api/user/vehicles", requireUserAuth, (req, res) => {
  const { make, model, reg_month, reg_year } = req.body;
  const makeStr = String(make || "").trim();
  const modelStr = String(model || "").trim();
  const month = reg_month ? Number(reg_month) : null;
  const year = reg_year ? Number(reg_year) : null;

  if (month !== null && (month < 1 || month > 12)) return res.status(400).json({ ok: false, error: "INVALID_MONTH" });
  if (year !== null && (year < 1900 || year > new Date().getFullYear())) return res.status(400).json({ ok: false, error: "INVALID_YEAR" });

  const pickerl = parsePickerlFields(req.body?.pickerl_month, req.body?.pickerl_year);
  if (pickerl.error) return res.status(400).json({ ok: false, error: pickerl.error });

  const result = db.prepare(
    "INSERT INTO vehicles (user_id, make, model, reg_month, reg_year, pickerl_month, pickerl_year) VALUES (?, ?, ?, ?, ?, ?, ?)"
  ).run(req.user.userId, makeStr || null, modelStr || null, month, year, pickerl.month, pickerl.year);

  const vehicle = db.prepare("SELECT * FROM vehicles WHERE id = ?").get(result.lastInsertRowid);
  return res.status(201).json({ ok: true, vehicle });
});

// PUT /api/user/vehicles/:id — редактиране на автомобил
app.put("/api/user/vehicles/:id", requireUserAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  const vehicle = db.prepare("SELECT id, user_id FROM vehicles WHERE id = ?").get(id);
  if (!vehicle) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  if (vehicle.user_id !== req.user.userId) return res.status(403).json({ ok: false, error: "FORBIDDEN" });

  const { make, model, reg_month, reg_year } = req.body;
  const makeStr = String(make || "").trim();
  const modelStr = String(model || "").trim();
  const month = reg_month ? Number(reg_month) : null;
  const year = reg_year ? Number(reg_year) : null;

  if (month !== null && (month < 1 || month > 12)) return res.status(400).json({ ok: false, error: "INVALID_MONTH" });
  if (year !== null && (year < 1900 || year > new Date().getFullYear())) return res.status(400).json({ ok: false, error: "INVALID_YEAR" });

  // App versions released before Pickerl support send PUT without these keys
  // at all; keep the stored values then instead of wiping a confirmed date.
  // An explicit null (key present) still clears it.
  const body = req.body || {};
  const sendsPickerl = Object.prototype.hasOwnProperty.call(body, "pickerl_month") ||
    Object.prototype.hasOwnProperty.call(body, "pickerl_year");
  const stored = db.prepare("SELECT pickerl_month, pickerl_year FROM vehicles WHERE id = ?").get(id);
  const pickerl = sendsPickerl
    ? parsePickerlFields(body.pickerl_month, body.pickerl_year)
    : { month: stored?.pickerl_month ?? null, year: stored?.pickerl_year ?? null };
  if (pickerl.error) return res.status(400).json({ ok: false, error: pickerl.error });

  db.prepare(
    "UPDATE vehicles SET make = ?, model = ?, reg_month = ?, reg_year = ?, pickerl_month = ?, pickerl_year = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
  ).run(makeStr || null, modelStr || null, month, year, pickerl.month, pickerl.year, id);

  const updated = db.prepare("SELECT * FROM vehicles WHERE id = ?").get(id);
  return res.json({ ok: true, vehicle: updated });
});

// DELETE /api/user/vehicles/:id — изтриване (готов за Фаза 2+)
app.delete("/api/user/vehicles/:id", requireUserAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  const vehicle = db.prepare("SELECT id, user_id FROM vehicles WHERE id = ?").get(id);
  if (!vehicle) return res.status(404).json({ ok: false, error: "NOT_FOUND" });
  if (vehicle.user_id !== req.user.userId) return res.status(403).json({ ok: false, error: "FORBIDDEN" });

  db.prepare("DELETE FROM vehicles WHERE id = ?").run(id);
  return res.json({ ok: true });
});

// ======================
// ERRORS (always JSON, never a stack trace or internal path)
// ======================
app.use("/api", (req, res) => res.status(404).json({ ok: false, error: "NOT_FOUND" }));

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") return res.status(413).json({ ok: false, error: "FILE_TOO_LARGE" });
    if (err.code === "LIMIT_FILE_COUNT" || err.code === "LIMIT_UNEXPECTED_FILE") {
      return res.status(400).json({ ok: false, error: "TOO_MANY_FILES" });
    }
    return res.status(400).json({ ok: false, error: "INVALID_UPLOAD" });
  }
  if (err?.type === "entity.parse.failed") return res.status(400).json({ ok: false, error: "INVALID_JSON" });
  if (err?.type === "entity.too.large") return res.status(413).json({ ok: false, error: "PAYLOAD_TOO_LARGE" });
  // Our own httpError(...) values (CORS_NOT_ALLOWED, INVALID_UPLOAD)
  if (err?.status >= 400 && err.status < 500 && /^[A-Z_]+$/.test(String(err.code || ""))) {
    return res.status(err.status).json({ ok: false, error: err.code });
  }
  if (err?.status === 400 || err?.statusCode === 400) return res.status(400).json({ ok: false, error: "BAD_REQUEST" });

  console.error("Unhandled error:", req.method, req.originalUrl.split("?")[0], err?.message || err);
  return res.status(500).json({ ok: false, error: "SERVER_ERROR" });
});

// ======================
// START
// ======================
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT} (env: ${NODE_ENV})`));