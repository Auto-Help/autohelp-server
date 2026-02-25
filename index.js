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

const app = express();

// Body parsers (keep early, before routes)
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ======================
// CONFIG (.env)
// ======================
const PORT = process.env.PORT || 4000;

// Frontend base URL (used in reset link)
const APP_BASE_URL = process.env.APP_BASE_URL || "http://localhost:5173";

// CORS allowed origins:
// - You can set one origin in APP_ORIGIN
// - Or multiple comma-separated in APP_ORIGINS (recommended for prod)
// Examples:
// APP_ORIGINS=https://yourdomain.com,https://www.yourdomain.com,capacitor://localhost,http://localhost:5173
const APP_ORIGIN = (process.env.APP_ORIGIN || "").trim();
const APP_ORIGINS = (process.env.APP_ORIGINS || "")
  .split(",")
  .map((x) => x.trim())
  .filter(Boolean);

// JWT
const JWT_SECRET = (process.env.JWT_SECRET || "").trim();
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "30d";

// SMTP
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;

// DB
const DB_FILE = process.env.DB_FILE || "./autohelp.sqlite";

// Environment
const NODE_ENV = (process.env.NODE_ENV || "development").toLowerCase();
const IS_PROD = NODE_ENV === "production";

// Fail fast in production if secret missing
if (IS_PROD && !JWT_SECRET) {
  console.error("❌ JWT_SECRET is missing in production. Server refused to start.");
  process.exit(1);
}

// Dev fallback only (safe-ish)
const EFFECTIVE_JWT_SECRET = JWT_SECRET || "CHANGE_ME_DEV_SECRET";

// ======================
// REQUEST LOGS (Render Logs friendly)
// ======================
app.use(morgan(":method :url :status - :response-time ms"));
app.use((req, res, next) => {
  // Helpful for CORS debugging
  console.log(
    "[REQ]",
    req.method,
    req.originalUrl,
    "| origin:",
    req.headers.origin || "(none)",
    "| ua:",
    (req.headers["user-agent"] || "").slice(0, 80)
  );
  next();
});

// ======================
// CORS
// ======================
function isAllowedOrigin(origin) {
  if (!origin) return true; // mobile apps / server-to-server / dev tools

  // From env list
  if (APP_ORIGIN && origin === APP_ORIGIN) return true;
  if (APP_ORIGINS.length > 0 && APP_ORIGINS.includes(origin)) return true;

  // Capacitor / Ionic schemes
  if (origin === "capacitor://localhost") return true;
  if (origin === "ionic://localhost") return true;

  // Allow localhost in dev only
  if (!IS_PROD) {
    if (origin.startsWith("http://localhost:")) return true;
    if (origin.startsWith("http://127.0.0.1:")) return true;
    if (origin === "capacitor://localhost") return true;
  }

  return false;
}

const corsOptions = {
  origin: (origin, cb) => {
    if (isAllowedOrigin(origin)) return cb(null, true);

    console.log("❌ CORS BLOCKED origin:", origin);
    // Returning an error makes the problem explicit in logs
    return cb(new Error("Not allowed by CORS: " + origin), false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
// IMPORTANT: handle preflight for all routes
app.options("*", cors(corsOptions));

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

  -- Ratings: 1 vote per (userId, serviceId) forever
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
`);

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
  return jwt.sign(payload, EFFECTIVE_JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function requireUserAuth(req, res, next) {
  const auth = String(req.headers.authorization || "");
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ ok: false, error: "NO_TOKEN" });

  try {
    const decoded = jwt.verify(m[1], EFFECTIVE_JWT_SECRET);
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
    const decoded = jwt.verify(m[1], EFFECTIVE_JWT_SECRET);
    if (!decoded || decoded.type !== "company" || !decoded.companyId) {
      return res.status(401).json({ ok: false, error: "INVALID_TOKEN" });
    }
    req.company = { companyId: decoded.companyId };
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: "INVALID_TOKEN" });
  }
}

// ======================
// TEXTS for FORGOT/RESET
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
// HEALTH / BASIC TEST
// ======================
app.get("/", (req, res) => {
  res.send("AutoHelp server is running ✅");
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    env: NODE_ENV,
    hasSmtp: hasSmtp(),
    time: new Date().toISOString(),
  });
});

// Debug endpoints (TEMP - remove after fixed)
app.get("/debug/cors", (req, res) => {
  res.json({
    ok: true,
    origin: req.headers.origin || null,
    method: req.method,
  });
});

app.post("/debug/echo", (req, res) => {
  res.json({
    ok: true,
    origin: req.headers.origin || null,
    headers: req.headers,
    body: req.body,
  });
});

// ======================
// AUTH: REGISTER USER
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

  return res.json({
    ok: true,
    token,
    user: { id, email: e, username: u, firstName: fn, lastName: ln, createdAt },
  });
});

// ======================
// AUTH: LOGIN USER (email OR username)
// ======================
app.post("/api/auth/login-user", (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (!password || (!email && !username)) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }

  let row = null;
  if (email) row = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  else row = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

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

// ======================
// AUTH: REGISTER COMPANY
// ======================
app.post("/api/auth/register-company", (req, res) => {
  const { companyName = "", phone = "", address = "", email = "", password = "", categories = [] } = req.body || {};
  const e = normalizeEmail(email);

  if (
    !String(companyName).trim() ||
    !String(phone).trim() ||
    !String(address).trim() ||
    !e ||
    String(password).length < 6 ||
    !Array.isArray(categories) ||
    categories.length === 0
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

  db.prepare(
    "INSERT INTO companies (id, email, companyName, phone, address, passwordHash, categoriesJson, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
  ).run(
    id,
    e,
    String(companyName).trim(),
    String(phone).trim(),
    String(address).trim(),
    passwordHash,
    JSON.stringify(categories),
    createdAt
  );

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
      categories,
      createdAt,
    },
  });
});

// ======================
// AUTH: LOGIN COMPANY
// ======================
app.post("/api/auth/login-company", (req, res) => {
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
      categories: JSON.parse(row.categoriesJson || "[]"),
      createdAt: row.createdAt,
    },
  });
});

// ======================
// FORGOT / RESET PASSWORD
// ======================

// reset token store: token => { email, expiresAt }
const resetTokens = new Map();

setInterval(() => {
  const now = Date.now();
  for (const [token, entry] of resetTokens.entries()) {
    if (!entry || now > entry.expiresAt) resetTokens.delete(token);
  }
}, 60 * 1000);

function findAccountByEmail(email) {
  const e = normalizeEmail(email);
  const u = db.prepare("SELECT id, email FROM users WHERE email = ?").get(e);
  if (u) return { type: "user", id: u.id, email: u.email };
  const c = db.prepare("SELECT id, email FROM companies WHERE email = ?").get(e);
  if (c) return { type: "company", id: c.id, email: c.email };
  return null;
}

function updatePasswordByEmail(email, newPassword) {
  const e = normalizeEmail(email);
  const passwordHash = bcrypt.hashSync(String(newPassword), 10);

  const u = db.prepare("SELECT id FROM users WHERE email = ?").get(e);
  if (u) {
    db.prepare("UPDATE users SET passwordHash = ? WHERE id = ?").run(passwordHash, u.id);
    return true;
  }

  const c = db.prepare("SELECT id FROM companies WHERE email = ?").get(e);
  if (c) {
    db.prepare("UPDATE companies SET passwordHash = ? WHERE id = ?").run(passwordHash, c.id);
    return true;
  }

  return false;
}

/**
 * POST /api/auth/forgot-password
 * body: { email, lang }
 * Връща винаги OK (за сигурност), дори да няма такъв email.
 */
app.post("/api/auth/forgot-password", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const lang = String(req.body?.lang || "en");
  const genericOk = { ok: true, message: msg(lang, "genericSent") };

  if (!email) return res.json(genericOk);

  const acc = findAccountByEmail(email);
  if (!acc) return res.json(genericOk);

  if (!hasSmtp()) {
    console.warn("⚠️ SMTP not configured (.env). Cannot send emails yet.");
    return res.json(genericOk);
  }

  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = nowMs() + 30 * 60 * 1000;
  resetTokens.set(token, { email, expiresAt });

  const resetLink = `${APP_BASE_URL}/reset-password?token=${encodeURIComponent(token)}`;

  try {
    const transporter = getTransporter();
    await transporter.sendMail({
      from: SMTP_FROM,
      to: email,
      subject: msg(lang, "subject"),
      text: msg(lang, "emailText")(resetLink),
    });
  } catch (e) {
    console.error("sendMail error:", e);
  }

  return res.json(genericOk);
});

/**
 * POST /api/auth/reset-password
 * body: { token, newPassword }
 */
app.post("/api/auth/reset-password", (req, res) => {
  const token = String(req.body?.token || "").trim();
  const newPassword = String(req.body?.newPassword || "");

  if (!token || newPassword.length < 6) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }

  const entry = resetTokens.get(token);
  if (!entry) return res.status(400).json({ ok: false, error: "TOKEN_INVALID" });

  if (nowMs() > entry.expiresAt) {
    resetTokens.delete(token);
    return res.status(400).json({ ok: false, error: "TOKEN_EXPIRED" });
  }

  const changed = updatePasswordByEmail(entry.email, newPassword);
  resetTokens.delete(token);

  if (!changed) return res.status(400).json({ ok: false, error: "ACCOUNT_NOT_FOUND" });

  return res.json({ ok: true });
});

// ======================
// RATINGS (1 vote per user per service)
// ======================

/**
 * POST /api/ratings
 * headers: Authorization: Bearer <token>  (USER token)
 * body: { serviceId, value } value: 1..5
 *
 * Rule: user can vote only once per service.
 * If already voted -> 409 ALREADY_VOTED
 */
app.post("/api/ratings", requireUserAuth, (req, res) => {
  const userId = req.user.userId;
  const serviceId = String(req.body?.serviceId || "").trim();
  const value = Number(req.body?.value);

  if (!serviceId || !Number.isInteger(value) || value < 1 || value > 5) {
    return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
  }

  const existing = db
    .prepare("SELECT id FROM ratings WHERE userId = ? AND serviceId = ?")
    .get(userId, serviceId);

  if (existing) {
    return res.status(409).json({ ok: false, error: "ALREADY_VOTED" });
  }

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

  const stats = db
    .prepare("SELECT AVG(value) as avg, COUNT(*) as votes FROM ratings WHERE serviceId = ?")
    .get(serviceId);

  return res.status(201).json({
    ok: true,
    rating: { id, serviceId, value, createdAt },
    stats: {
      average: Number(stats?.avg || 0),
      votes: Number(stats?.votes || 0),
    },
  });
});

/**
 * GET /api/ratings/stats/:serviceId
 */
app.get("/api/ratings/stats/:serviceId", (req, res) => {
  const serviceId = String(req.params.serviceId || "").trim();
  if (!serviceId) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  const stats = db
    .prepare("SELECT AVG(value) as avg, COUNT(*) as votes FROM ratings WHERE serviceId = ?")
    .get(serviceId);

  return res.json({
    ok: true,
    serviceId,
    average: Number(stats?.avg || 0),
    votes: Number(stats?.votes || 0),
  });
});

// ======================
// START
// ======================
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT} (env: ${NODE_ENV})`));