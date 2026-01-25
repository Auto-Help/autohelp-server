// AutoHelp-server/index.js
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");

const app = express();
app.use(express.json());

// ======================
// CONFIG (.env)
// ======================
const PORT = process.env.PORT || 4000;

// Backwards compatible handling
const RAW_APP_BASE_URL = process.env.APP_BASE_URL || "http://localhost:5173";
const looksLikeScheme =
  String(RAW_APP_BASE_URL).includes("://") && !String(RAW_APP_BASE_URL).startsWith("http");

const WEB_ORIGIN =
  process.env.WEB_ORIGIN ||
  process.env.CORS_ORIGIN ||
  (looksLikeScheme ? "http://localhost:5173" : RAW_APP_BASE_URL);

// ✅ IMPORTANT: Your app.json scheme is "autohelp"
// so deep link base must be "autohelp://"
const APP_DEEP_LINK_BASE =
  process.env.APP_DEEP_LINK_BASE ||
  (looksLikeScheme ? RAW_APP_BASE_URL : "autohelp://");

// Expo Go fallback base (optional)
const EXP_DEEP_LINK_BASE = String(process.env.EXP_DEEP_LINK_BASE || "").trim().replace(/\/+$/, "");

// JWT
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_ME_DEV_SECRET";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "30d";

// SMTP
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER;

// DB
const DB_FILE = process.env.DB_FILE || "/data/autohelp.sqlite";

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

      if (origin.startsWith("http://localhost:")) return cb(null, true);
      if (origin.startsWith("http://127.0.0.1:")) return cb(null, true);

      return cb(null, false);
    },
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

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
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
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

// ✅ Do not break scheme://
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
// BASIC TEST
// ======================
app.get("/", (req, res) => {
  res.send("AutoHelp server is running ✅");
});

// ======================
// RESET PASSWORD LANDING PAGE
// ======================
app.get("/reset-password", (req, res) => {
  const token = String(req.query.token || "");
  const deepBase = normalizeDeepLinkBase(APP_DEEP_LINK_BASE);

  // ✅ Correct Expo Router deep link path format:
  // autohelp:///reset-password?token=...
  const appLink = `${deepBase}///reset-password?token=${encodeURIComponent(token)}`;

  // Expo Go fallback (optional)
  const expoGoLink = EXP_DEEP_LINK_BASE
    ? `${EXP_DEEP_LINK_BASE}/--/reset-password?token=${encodeURIComponent(token)}`
    : "";

  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`
<!doctype html>
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
      // Try open app
      setTimeout(() => { window.location.href = "${appLink}"; }, 200);
      ${expoGoLink ? `setTimeout(() => { window.location.href = "${expoGoLink}"; }, 900);` : ""}
    </script>
  </body>
</html>
  `);
});

// ======================
// DEMO GARAGES API
// ======================
const garages = [
  {
    id: 1,
    name: "AGW / KFZ Technik",
    address: "Liesinger-Flur Gasse 15, 1230 Wien",
    phone: "+43 664 882 32500",
    services: {
      de: ["Öl- und Filterwechsel", "Spülungen", "Automatikgetriebe-Ölwechsel", "Diagnose"],
      en: ["Oil and filter change", "Engine flush", "Automatic transmission oil change", "Diagnostics"],
      bg: ["Смяна на масла и филтри", "Промивки", "Смяна на масла на автоматични кутии", "Диагностика"],
    },
  },
];

app.get("/garages", (req, res) => {
  res.json(garages);
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
// AUTH: LOGIN USER
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

app.post("/api/auth/forgot-password", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const lang = String(req.body?.lang || "en");
  const genericOk = { ok: true, message: msg(lang, "genericSent") };

  if (!email) return res.json(genericOk);

  const acc = findAccountByEmail(email);
  if (!acc) return res.json(genericOk);

  if (!hasSmtp()) return res.json(genericOk);

  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = nowMs() + 30 * 60 * 1000;
  resetTokens.set(token, { email, expiresAt });

  const publicBase = getPublicBaseUrl(req);
  const resetLink = `${publicBase}/reset-password?token=${encodeURIComponent(token)}`;

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
// RATINGS
// ======================
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

  const stats = db.prepare("SELECT AVG(value) as avg, COUNT(*) as votes FROM ratings WHERE serviceId = ?").get(serviceId);

  return res.status(201).json({
    ok: true,
    rating: { id, serviceId, value, createdAt },
    stats: {
      average: Number(stats?.avg || 0),
      votes: Number(stats?.votes || 0),
    },
  });
});

app.get("/api/ratings/stats/:serviceId", (req, res) => {
  const serviceId = String(req.params.serviceId || "").trim();
  if (!serviceId) return res.status(400).json({ ok: false, error: "INVALID_INPUT" });

  const stats = db.prepare("SELECT AVG(value) as avg, COUNT(*) as votes FROM ratings WHERE serviceId = ?").get(serviceId);

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
app.listen(PORT, () => console.log(`✅ Server running on http://localhost:${PORT}`));
