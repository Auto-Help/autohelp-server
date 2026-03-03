// autohelp-server/auth.js (CommonJS) - FIXED to match current SQLite schema
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

module.exports = function createAuthRouter(db) {
  const router = express.Router();
  const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

  const signToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });

  const nowMs = () => Date.now();
  const createId = (prefix) => `${prefix}_${crypto.randomBytes(10).toString("hex")}`;
  const normalizeEmail = (email) => String(email || "").trim().toLowerCase();

  // ---- USER REGISTER
  router.post("/register-user", (req, res) => {
    const { firstName = "", lastName = "", username = "", email = "", password = "" } = req.body || {};
    const fn = String(firstName).trim();
    const ln = String(lastName).trim();
    const u = String(username).trim();
    const e = normalizeEmail(email);
    const p = String(password || "");

    if (!fn || !ln || !u || !e || p.length < 6) {
      return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
    }

    const exists =
      db.prepare("SELECT 1 FROM users WHERE email = ?").get(e) ||
      db.prepare("SELECT 1 FROM companies WHERE email = ?").get(e);

    if (exists) return res.status(409).json({ ok: false, error: "EMAIL_EXISTS" });

    const id = createId("u");
    const passwordHash = bcrypt.hashSync(p, 10);
    const createdAt = nowMs();

    db.prepare(
      "INSERT INTO users (id, email, username, firstName, lastName, passwordHash, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).run(id, e, u, fn, ln, passwordHash, createdAt);

    const token = signToken({ type: "user", userId: id });
    return res.json({ ok: true, token, user: { id, email: e, username: u, firstName: fn, lastName: ln, createdAt } });
  });

  // ---- USER LOGIN (email OR username)
  router.post("/login-user", (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");

    if (!password || (!email && !username)) {
      return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
    }

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

  // ---- COMPANY REGISTER (minimal version; your main one is in index.js)
  router.post("/register-company", (req, res) => {
    const { companyName = "", phone = "", address = "", email = "", password = "", categories = [] } = req.body || {};
    const cn = String(companyName).trim();
    const ph = String(phone).trim();
    const ad = String(address).trim();
    const e = normalizeEmail(email);
    const p = String(password || "");

    if (!cn || !ph || !ad || !e || p.length < 6 || !Array.isArray(categories) || categories.length === 0) {
      return res.status(400).json({ ok: false, error: "INVALID_INPUT" });
    }

    const exists =
      db.prepare("SELECT 1 FROM users WHERE email = ?").get(e) ||
      db.prepare("SELECT 1 FROM companies WHERE email = ?").get(e);

    if (exists) return res.status(409).json({ ok: false, error: "EMAIL_EXISTS" });

    const id = createId("c");
    const passwordHash = bcrypt.hashSync(p, 10);
    const createdAt = nowMs();

    db.prepare(
      "INSERT INTO companies (id, email, companyName, phone, address, passwordHash, categoriesJson, createdAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(id, e, cn, ph, ad, passwordHash, JSON.stringify(categories), createdAt);

    const token = signToken({ type: "company", companyId: id });
    return res.json({ ok: true, token, company: { id, email: e, companyName: cn, phone: ph, address: ad, categories, createdAt } });
  });

  // ---- COMPANY LOGIN
  router.post("/login-company", (req, res) => {
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

  return router;
};