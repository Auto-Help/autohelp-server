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
const fs = require("fs");
const path = require("path");

// ✅ UPLOAD (LOCAL /data/uploads on Render Persistent Disk)
const multer = require("multer");

const app = express();

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

// ======================
// LOGS
// ======================
app.use(morgan(":method :url :status - :response-time ms"));

// ======================
// SIMPLE RATE LIMIT (in-memory)
// ======================
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
    const ip = String(req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown")
      .split(",")[0]
      .trim();
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

app.use(
  cors({
    origin: (origin, cb) => {
      if (isAllowedOrigin(origin)) return cb(null, true);
      return cb(new Error("CORS_NOT_ALLOWED"), false);
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  })
);

// Preflight
app.options("*", cors());

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

// ✅ serve: https://your-server.onrender.com/uploads/<file>
app.use("/uploads", express.static(UPLOAD_DIR, { maxAge: "7d", etag: true }));

function hasUploads() {
  try {
    fs.accessSync(UPLOAD_DIR, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
}

function extFromMime(mime) {
  const m = String(mime || "").toLowerCase();
  if (m === "image/jpeg") return ".jpg";
  if (m === "image/png") return ".png";
  if (m === "image/webp") return ".webp";
  if (m === "image/gif") return ".gif";
  if (m === "image/heic" || m === "image/heif") return ".heic";
  return "";
}

function safeFileName(companyId, kind, originalName, mime) {
  const rand = crypto.randomBytes(12).toString("hex");
  const ext =
    path.extname(String(originalName || "")).slice(0, 10) ||
    extFromMime(mime) ||
    ".bin";
  return `${companyId}_${kind}_${Date.now()}_${rand}${ext}`;
}

// Multer disk storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const companyId = req.company?.companyId || "unknown";
    const kind = file.fieldname === "logo" ? "logo" : "img";
    cb(null, safeFileName(companyId, kind, file.originalname, file.mimetype));
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB per file
  fileFilter: (req, file, cb) => {
    const m = String(file.mimetype || "").toLowerCase();
    if (
      m === "image/jpeg" ||
      m === "image/png" ||
      m === "image/webp" ||
      m === "image/gif" ||
      m === "image/heic" ||
      m === "image/heif"
    ) {
      return cb(null, true);
    }
    return cb(new Error("ONLY_IMAGES_ALLOWED"));
  },
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
    req.company = { companyId: decoded.companyId };
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "INVALID_TOKEN" });
  }
}

// Render / proxy safe base URL
function getPublicBaseUrl(req) {
  const forced = String(process.env.PUBLIC_BASE_URL || "").trim();
  if (forced) return forced.replace(/\/+$/, "");

  const proto = String(req.headers["x-forwarded-proto"] || req.protocol || "https")
    .split(",")[0]
    .trim();
  const host = String(req.headers["x-forwarded-host"] || req.get("host") || "")
    .split(",")[0]
    .trim();
  return `${proto}://${host}`.replace(/\/+$/, "");
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

// Working hours helper
function isOpenNow(workingHoursJson) {
  if (!workingHoursJson) return null;
  let data = null;
  try {
    data = JSON.parse(workingHoursJson);
  } catch {
    return null;
  }

  const now = new Date();
  const dayIdx = now.getDay();
  const dayKey = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"][dayIdx];
  const hh = String(now.getHours()).padStart(2, "0");
  const mm = String(now.getMinutes()).padStart(2, "0");
  const cur = `${hh}:${mm}`;

  if (data && typeof data === "object" && !Array.isArray(data)) {
    const slots = data[dayKey];
    if (!Array.isArray(slots)) return null;
    for (const s of slots) {
      if (Array.isArray(s) && s.length >= 2) {
        const from = String(s[0]);
        const to = String(s[1]);
        if (from <= cur && cur <= to) return true;
      }
    }
    return false;
  }

  if (Array.isArray(data)) {
    const slots = data.filter((x) => x && String(x.day).toLowerCase() === dayKey);
    if (!slots.length) return null;
    for (const s of slots) {
      const from = String(s.from || "");
      const to = String(s.to || "");
      if (from && to && from <= cur && cur <= to) return true;
    }
    return false;
  }

  return null;
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
  const v = dict[key];
  if (!v) return "";
  if (typeof v === "function") return v;
  return v[L] || v.en;
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
    uploadDir: UPLOAD_DIR,
    dbFile: DB_FILE,
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
app.post(
  "/api/company/upload-media",
  requireCompanyAuth,
  upload.fields([
    { name: "logo", maxCount: 1 },
    { name: "images", maxCount: 3 },
  ]),
  (req, res) => {
    try {
      if (!hasUploads()) {
        return res.status(500).json({ ok: false, error: "UPLOADS_NOT_AVAILABLE" });
      }

      const companyId = req.company.companyId;
      const base = getPublicBaseUrl(req);

      const logoFile = req.files?.logo?.[0] || null;
      const imageFiles = Array.isArray(req.files?.images) ? req.files.images : [];

      let logoUrl = null;
      const images = [];

      if (logoFile?.filename) {
        logoUrl = `${base}/uploads/${encodeURIComponent(logoFile.filename)}`;
      }

      for (const f of imageFiles.slice(0, 3)) {
        if (f?.filename) images.push(`${base}/uploads/${encodeURIComponent(f.filename)}`);
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
      const msg = String(e?.message || "");
      if (msg.includes("ONLY_IMAGES_ALLOWED")) {
        return res.status(400).json({ ok: false, error: "ONLY_IMAGES_ALLOWED" });
      }
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

<script>
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

  if (!row) return res.status(401).json({ ok: false, error: "INVALID_LOGIN" });

  const ok = bcrypt.compareSync(password, row.passwordHash);
  if (!ok) return res.status(401).json({ ok: false, error: "INVALID_LOGIN" });

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

  // New companies must register with a full international (E.164) phone number.
  const phoneE164 = normalizePhoneInput(phone);
  if (!isE164Phone(phoneE164)) {
    return res.status(400).json({ ok: false, error: "PHONE_INVALID" });
  }

  const exists =
    db.prepare("SELECT 1 FROM users WHERE email = ?").get(e) ||
    db.prepare("SELECT 1 FROM companies WHERE email = ?").get(e);

  if (exists) return res.status(409).json({ ok: false, error: "EMAIL_EXISTS" });

  const id = createId("c");
  const passwordHash = bcrypt.hashSync(String(password), 10);
  const createdAt = nowMs();

  const latNum = lat === null || lat === undefined || lat === "" ? null : Number(lat);
  const lngNum = lng === null || lng === undefined || lng === "" ? null : Number(lng);

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
    vals.push(workingHoursJson ? String(workingHoursJson) : null);
  }

  // ✅ NEW: servicesText column exists? Insert empty default (safe)
  if (hasColumn("companies", "servicesText")) {
    cols.push("servicesText");
    vals.push("");
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
      // ✅ NEW
      servicesText: "",
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
  if (!row) return res.status(401).json({ ok: false, error: "INVALID_LOGIN" });

  const ok = bcrypt.compareSync(password, row.passwordHash);
  if (!ok) return res.status(401).json({ ok: false, error: "INVALID_LOGIN" });

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
    if (current && normalizeEmail(current.email) !== emailNew) {
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

  const latNum = lat === null || lat === undefined || lat === "" ? null : Number(lat);
  const lngNum = lng === null || lng === undefined || lng === "" ? null : Number(lng);

  const sets = [];
  const vals = [];

  if (hasColumn("companies", "lat")) {
    sets.push("lat = ?");
    vals.push(Number.isFinite(latNum) ? latNum : null);
  }
  if (hasColumn("companies", "lng")) {
    sets.push("lng = ?");
    vals.push(Number.isFinite(lngNum) ? lngNum : null);
  }
  if (hasColumn("companies", "workingHoursJson") && workingHoursJson !== undefined) {
    sets.push("workingHoursJson = ?");
    vals.push(workingHoursJson ? String(workingHoursJson) : null);
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

  if (!sets.length) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

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

  if (!email) return res.json(genericOk);

  const acc = findAccountByEmail(email);
  if (!acc) return res.json(genericOk);

  if (!hasSmtp()) return res.json(genericOk);

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

  return res.json(genericOk);
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

  const existing = db.prepare("SELECT id FROM users WHERE email = ? AND id != ?").get(email, req.user.userId);
  if (existing) return res.status(409).json({ ok: false, error: "EMAIL_EXISTS" });

  db.prepare("UPDATE users SET email = ? WHERE id = ?").run(email, req.user.userId);
  return res.json({ ok: true });
});

// PUT /api/user/password — смяна на парола
app.put("/api/user/password", requireUserAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  if (String(newPassword).length < 6) return res.status(400).json({ ok: false, error: "PASS_TOO_SHORT" });

  const user = db.prepare("SELECT passwordHash FROM users WHERE id = ?").get(req.user.userId);
  if (!user) return res.status(404).json({ ok: false, error: "NOT_FOUND" });

  const match = bcrypt.compareSync(String(currentPassword), user.passwordHash);
  if (!match) return res.status(401).json({ ok: false, error: "WRONG_PASSWORD" });

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
// START
// ======================
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT} (env: ${NODE_ENV})`));