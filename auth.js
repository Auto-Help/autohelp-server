// autohelp-server/auth.js (CommonJS)
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

module.exports = function createAuthRouter(db) {
  const router = express.Router();
  const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

  // ---- helpers
  const signToken = (payload) => jwt.sign(payload, JWT_SECRET, { expiresIn: "30d" });

  // ---- USER REGISTER
  router.post("/register-user", (req, res) => {
    const { username, email, password } = req.body || {};
    const u = String(username || "").trim();
    const e = String(email || "").trim().toLowerCase();
    const p = String(password || "");

    if (!u || !e || !p) return res.status(400).json({ ok: false, message: "Missing fields" });

    const exists = db
      .prepare("SELECT id FROM users WHERE email = ? OR username = ?")
      .get(e, u);

    if (exists) return res.status(409).json({ ok: false, message: "User already exists" });

    const hash = bcrypt.hashSync(p, 10);
    const info = db
      .prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)")
      .run(u, e, hash);

    const user = { id: info.lastInsertRowid, username: u, email: e };
    const token = signToken({ type: "user", id: user.id });

    return res.json({ ok: true, token, user });
  });

  // ---- USER LOGIN
  router.post("/login-user", (req, res) => {
    const { username, email, password } = req.body || {};
    const u = String(username || "").trim();
    const e = String(email || "").trim().toLowerCase();
    const p = String(password || "");

    if ((!u && !e) || !p) return res.status(400).json({ ok: false, message: "Missing fields" });

    const row = e
      ? db.prepare("SELECT * FROM users WHERE email = ?").get(e)
      : db.prepare("SELECT * FROM users WHERE username = ?").get(u);

    if (!row) return res.status(401).json({ ok: false, message: "Invalid credentials" });

    const ok = bcrypt.compareSync(p, row.password_hash);
    if (!ok) return res.status(401).json({ ok: false, message: "Invalid credentials" });

    const user = { id: row.id, username: row.username, email: row.email };
    const token = signToken({ type: "user", id: user.id });

    return res.json({ ok: true, token, user });
  });

  // ---- COMPANY REGISTER
  router.post("/register-company", (req, res) => {
    const { name, email, password } = req.body || {};
    const n = String(name || "").trim();
    const e = String(email || "").trim().toLowerCase();
    const p = String(password || "");

    if (!n || !e || !p) return res.status(400).json({ ok: false, message: "Missing fields" });

    const exists = db.prepare("SELECT id FROM companies WHERE email = ?").get(e);
    if (exists) return res.status(409).json({ ok: false, message: "Company already exists" });

    const hash = bcrypt.hashSync(p, 10);
    const info = db
      .prepare("INSERT INTO companies (name, email, password_hash) VALUES (?, ?, ?)")
      .run(n, e, hash);

    const company = { id: info.lastInsertRowid, name: n, email: e };
    const token = signToken({ type: "company", id: company.id });

    return res.json({ ok: true, token, company });
  });

  // ---- COMPANY LOGIN
  router.post("/login-company", (req, res) => {
    const { email, password } = req.body || {};
    const e = String(email || "").trim().toLowerCase();
    const p = String(password || "");

    if (!e || !p) return res.status(400).json({ ok: false, message: "Missing fields" });

    const row = db.prepare("SELECT * FROM companies WHERE email = ?").get(e);
    if (!row) return res.status(401).json({ ok: false, message: "Invalid credentials" });

    const ok = bcrypt.compareSync(p, row.password_hash);
    if (!ok) return res.status(401).json({ ok: false, message: "Invalid credentials" });

    const company = { id: row.id, name: row.name, email: row.email };
    const token = signToken({ type: "company", id: company.id });

    return res.json({ ok: true, token, company });
  });

  return router;
};
