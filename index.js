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

const rlLogin = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 20, keyPrefix: "login" });
const rlForgot = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 5, keyPrefix: "forgot" });
const rlReset = createRateLimiter({ windowMs: 15 * 60 * 1000, max: 10, keyPrefix: "reset" });

// ======================
// CORS
// ======================
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);

      if (WEB_ORIGIN && (WEB_ORIGIN.startsWith("http://") || WEB_ORIGIN.startsWith("https://"))) {
        if (origin === WEB_ORIGIN) return cb(null, true);
      }

      // dev
      if (!IS_PROD) {
        if (origin.startsWith("http://localhost:")) return cb(null, true);
        if (origin.startsWith("http://127.0.0.1:")) return cb(null, true);
      }

      return cb(null, false);
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  })
);
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

function normalizeDeepLinkBase(base) {
  let b = String(base || "").trim();
  if (!b) return "autohelp://";

  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(b)) {
    const idx = b.indexOf("://");
    const scheme = b.slice(0, idx);
    const rest = b.slice(idx + 3).replace(/\/+$/, "");
    return rest ? `${scheme}://${rest}` : `${scheme}://`;
  }

  return b.replace(/\/+$/, "");
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

      // ✅ запази в DB (замества с новите ако са подадени)
      db.prepare(
        "UPDATE companies SET logoUrl = COALESCE(?, logoUrl), imagesJson = COALESCE(?, imagesJson) WHERE id = ?"
      ).run(
        logoUrl,
        images.length ? JSON.stringify(images) : null,
        companyId
      );

      return res.json({ ok: true, logoUrl, images });
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
app.post("/api/auth/register-user", (req, res) => {
  const { firstName = "", lastName = "", username = "", email = "", password = "" } = req.body || {};
  const e = normalizeEmail(email);
  const u = String(username).trim();
  const fn = String(firstName).trim();
  const ln = String(lastName).trim();

  if (!fn || !ln || !u || !e || String(password).length < 6) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }

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
app.post("/api/auth/register-company", (req, res) => {
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
    String(phone).trim(),
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
      phone: String(phone).trim(),
      address: String(address).trim(),
      categories: normalizedCategories,
      lat: Number.isFinite(latNum) ? latNum : null,
      lng: Number.isFinite(lngNum) ? lngNum : null,
      createdAt,
    },
  });
});

app.post("/api/auth/login-company", rlLogin, (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || "");
  if (!email || !password) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  const row = db.prepare("SELECT * FROM companies WHERE email = ?").get(email);
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
// ✅ COMPANIES LIST
// GET /api/companies?category=inspection
// ======================
app.get("/api/companies", (req, res) => {
  const categoryRaw = req.query.category ? String(req.query.category) : "";
  const category = categoryRaw ? normalizeCategoryId(categoryRaw) : "";

  const rows = db.prepare(`SELECT * FROM companies`).all();

  const items = [];
  for (const c of rows) {
    const cats = parseCategories(c.categoriesJson);
    if (category && !cats.includes(category)) continue;

    const openNow = isOpenNow(c.workingHoursJson);
    const rating = getRatingStatsByCompanyId(c.id);

    items.push({
      id: c.id,
      email: c.email,
      companyName: c.companyName,
      phone: c.phone,
      address: c.address,
      categories: cats,
      lat: c.lat ?? null,
      lng: c.lng ?? null,
      openNow,
      rating,
      logoUrl: c.logoUrl ?? null,
      images: parseImages(c.imagesJson),
      createdAt: c.createdAt,
    });
  }

  items.sort((a, b) => {
    const aOpen = a.openNow === true ? 1 : 0;
    const bOpen = b.openNow === true ? 1 : 0;
    if (aOpen !== bOpen) return bOpen - aOpen;
    if (a.rating.average !== b.rating.average) return b.rating.average - a.rating.average;
    if (a.rating.votes !== b.rating.votes) return b.rating.votes - a.rating.votes;
    return Number(b.createdAt || 0) - Number(a.createdAt || 0);
  });

  return res.json({ ok: true, items, category });
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

  return res.json({ ok: true, serviceId, average: Number(stats?.avg || 0), votes: Number(stats?.votes || 0) });
});

// ======================
// ✅ DEBUG
// ======================
app.get("/api/debug/db", (req, res) => {
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
    .prepare("SELECT id, email, companyName, categoriesJson, lat, lng, logoUrl, imagesJson, createdAt FROM companies ORDER BY createdAt DESC LIMIT 5")
    .all()
    .map((r) => ({ ...r, categories: parseCategories(r.categoriesJson), images: parseImages(r.imagesJson) }));

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
// START
// ======================
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT} (env: ${NODE_ENV})`));