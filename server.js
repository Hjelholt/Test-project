const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const Database = require('better-sqlite3');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USER = process.env.ADMIN_USER || 'Admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret-in-production';

const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'app.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    date TEXT,
    time TEXT,
    location TEXT,
    emoji TEXT DEFAULT '🎉',
    created_at TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS registrations (
    id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS password_resets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
  );
`);

// Migrations — add new columns to events if they don't exist yet
try { db.exec(`ALTER TABLE events ADD COLUMN is_public INTEGER NOT NULL DEFAULT 1`); } catch {}
try { db.exec(`ALTER TABLE events ADD COLUMN access_token TEXT`); } catch {}
try { db.exec(`ALTER TABLE events ADD COLUMN owner_id TEXT REFERENCES users(id)`); } catch {}

// Backfill access_token for any existing events that don't have one
{
  const missing = db.prepare('SELECT id FROM events WHERE access_token IS NULL').all();
  const setToken = db.prepare('UPDATE events SET access_token = ? WHERE id = ?');
  for (const ev of missing) setToken.run(crypto.randomUUID(), ev.id);
}

// ── Optional email transport (set SMTP_HOST/USER/PASS env vars to enable) ───
const transporter = (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS)
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    })
  : null;

// ── Password utilities ────────────────────────────────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), crypto.scryptSync(password, salt, 64));
}

// ── Middleware ────────────────────────────────────────────────────
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 8 * 60 * 60 * 1000
  }
}));

// ── Auth middleware ───────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

function requireUser(req, res, next) {
  if (req.session.userId) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

function requireAuthOrUser(req, res, next) {
  if (req.session.authenticated || req.session.userId) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ── Prepared statements ──────────────────────────────────────────
const stmts = {
  // Users
  getUserByEmail:    db.prepare('SELECT * FROM users WHERE email = ?'),
  getUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  getUserById:       db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?'),
  insertUser:        db.prepare('INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)'),

  // Events
  getPublicEvents:   db.prepare("SELECT * FROM events WHERE is_public = 1 ORDER BY COALESCE(date, '9999') ASC"),
  getAllEvents:       db.prepare("SELECT * FROM events ORDER BY COALESCE(date, '9999') ASC"),
  getMyEvents:       db.prepare("SELECT * FROM events WHERE owner_id = ? ORDER BY COALESCE(date, '9999') ASC"),
  getEvent:          db.prepare('SELECT * FROM events WHERE id = ?'),
  getEventByToken:   db.prepare('SELECT * FROM events WHERE access_token = ?'),
  insertEvent:       db.prepare('INSERT INTO events (id, name, date, time, location, emoji, is_public, access_token, owner_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'),
  updateEvent:       db.prepare('UPDATE events SET name = ?, date = ?, time = ?, location = ?, emoji = ?, is_public = ? WHERE id = ?'),
  deleteEvent:       db.prepare('DELETE FROM events WHERE id = ?'),

  // Registrations
  getRegs:           db.prepare(`SELECT r.*, e.name AS event_name, e.emoji FROM registrations r LEFT JOIN events e ON r.event_id = e.id ORDER BY r.created_at DESC`),
  getRegsByEvent:    db.prepare(`SELECT r.*, e.name AS event_name, e.emoji FROM registrations r LEFT JOIN events e ON r.event_id = e.id WHERE r.event_id = ? ORDER BY r.created_at DESC`),
  getRegsByOwner:    db.prepare(`SELECT r.*, e.name AS event_name, e.emoji FROM registrations r LEFT JOIN events e ON r.event_id = e.id WHERE e.owner_id = ? ORDER BY r.created_at DESC`),
  getRegWithOwner:   db.prepare(`SELECT r.*, e.owner_id FROM registrations r LEFT JOIN events e ON r.event_id = e.id WHERE r.id = ?`),
  insertReset:       db.prepare('INSERT INTO password_resets (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)'),
  getResetByToken:   db.prepare('SELECT * FROM password_resets WHERE token = ? AND used = 0'),
  markResetUsed:     db.prepare('UPDATE password_resets SET used = 1 WHERE id = ?'),
  updatePassword:    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?'),
  insertReg:         db.prepare('INSERT INTO registrations (id, event_id, name, phone, created_at) VALUES (?, ?, ?, ?, ?)'),
  deleteReg:         db.prepare('DELETE FROM registrations WHERE id = ?'),
  deleteRegsByEvent: db.prepare('DELETE FROM registrations WHERE event_id = ?'),
};

// ── User auth routes ──────────────────────────────────────────────
app.post('/api/users/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username?.trim() || !email?.trim() || !password)
    return res.status(400).json({ error: 'Username, email and password are required.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (stmts.getUserByEmail.get(email.trim().toLowerCase()))
    return res.status(409).json({ error: 'Email already in use.' });
  if (stmts.getUserByUsername.get(username.trim()))
    return res.status(409).json({ error: 'Username already taken.' });

  const id = crypto.randomUUID();
  stmts.insertUser.run(id, username.trim(), email.trim().toLowerCase(), hashPassword(password), new Date().toISOString());
  req.session.userId = id;
  req.session.username = username.trim();
  res.json({ id, username: username.trim(), email: email.trim().toLowerCase() });
});

app.post('/api/users/login', (req, res) => {
  const { email, password } = req.body;
  if (!email?.trim() || !password)
    return res.status(400).json({ error: 'Email and password are required.' });
  const user = stmts.getUserByEmail.get(email.trim().toLowerCase());
  if (!user || !verifyPassword(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid email or password.' });
  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ id: user.id, username: user.username, email: user.email });
});

app.post('/api/users/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/users/me', requireUser, (req, res) => {
  const user = stmts.getUserById.get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found.' });
  res.json(user);
});

app.post('/api/users/forgot-password', async (req, res) => {
  const { email } = req.body;
  if (!email?.trim()) return res.status(400).json({ error: 'Email is required.' });
  const user = stmts.getUserByEmail.get(email.trim().toLowerCase());
  if (!user) return res.json({ success: true }); // don't reveal whether email exists

  const token = crypto.randomBytes(32).toString('hex');
  stmts.insertReset.run(crypto.randomUUID(), user.id, token, new Date(Date.now() + 3600_000).toISOString());

  const base = process.env.APP_URL || `${req.protocol}://${req.get('host')}`;
  const resetUrl = `${base}/dashboard.html?reset=${token}`;

  if (transporter) {
    try {
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: 'Password reset',
        text: `Reset your password here (link valid 1 hour):\n\n${resetUrl}`,
        html: `<p>Click the link to reset your password (valid 1 hour):</p><p><a href="${resetUrl}">${resetUrl}</a></p>`
      });
      return res.json({ success: true });
    } catch (err) {
      console.error('Email send failed:', err.message);
    }
  }
  // No email configured: return the link so the user can share it manually
  res.json({ success: true, resetUrl });
});

app.post('/api/users/reset-password', (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token and password are required.' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  const reset = stmts.getResetByToken.get(token);
  if (!reset || new Date(reset.expires_at) < new Date())
    return res.status(400).json({ error: 'Reset link is invalid or has expired.' });
  stmts.updatePassword.run(hashPassword(password), reset.user_id);
  stmts.markResetUsed.run(reset.id);
  res.json({ success: true });
});

app.get('/api/users/status', (req, res) => {
  res.json(req.session.userId
    ? { authenticated: true, userId: req.session.userId, username: req.session.username }
    : { authenticated: false });
});

// ── Admin auth routes ─────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.authenticated = true;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid username or password.' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/auth/status', (req, res) => {
  res.json({ authenticated: !!req.session.authenticated });
});

// ── Event routes ──────────────────────────────────────────────────

// Public events only — used by the registration page
app.get('/api/events', (req, res) => {
  res.json(stmts.getPublicEvents.all());
});

// All events — admin only
app.get('/api/events/all', requireAuth, (req, res) => {
  res.json(stmts.getAllEvents.all());
});

// Current user's events
app.get('/api/events/mine', requireUser, (req, res) => {
  res.json(stmts.getMyEvents.all(req.session.userId));
});

// Single event by access token — used for private event links
app.get('/api/events/by-token', (req, res) => {
  const ev = req.query.token ? stmts.getEventByToken.get(req.query.token) : null;
  if (!ev) return res.status(404).json({ error: 'Event not found.' });
  res.json(ev);
});

app.post('/api/events', requireAuthOrUser, (req, res) => {
  const { name, date, time, location, emoji, is_public } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Event name is required.' });

  const event = {
    id: crypto.randomUUID(),
    name: name.trim(),
    date: date || null,
    time: time || null,
    location: location?.trim() || null,
    emoji: emoji?.trim() || '🎉',
    is_public: is_public === false || is_public === 0 ? 0 : 1,
    access_token: crypto.randomUUID(),
    owner_id: req.session.authenticated ? null : req.session.userId,
    created_at: new Date().toISOString()
  };

  stmts.insertEvent.run(
    event.id, event.name, event.date, event.time,
    event.location, event.emoji, event.is_public,
    event.access_token, event.owner_id, event.created_at
  );
  res.json(event);
});

app.put('/api/events/:id', requireAuthOrUser, (req, res) => {
  const { name, date, time, location, emoji, is_public } = req.body;
  if (!name?.trim()) return res.status(400).json({ error: 'Event name is required.' });

  const existing = stmts.getEvent.get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Event not found.' });
  if (!req.session.authenticated && existing.owner_id !== req.session.userId)
    return res.status(403).json({ error: 'Forbidden.' });

  const isPublic = is_public === false || is_public === 0 ? 0 : 1;
  stmts.updateEvent.run(name.trim(), date || null, time || null, location?.trim() || null, emoji?.trim() || '🎉', isPublic, req.params.id);
  res.json({ ...existing, name: name.trim(), date: date || null, time: time || null, location: location?.trim() || null, emoji: emoji?.trim() || '🎉', is_public: isPublic });
});

app.delete('/api/events/:id', requireAuthOrUser, (req, res) => {
  const existing = stmts.getEvent.get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Event not found.' });
  if (!req.session.authenticated && existing.owner_id !== req.session.userId)
    return res.status(403).json({ error: 'Forbidden.' });
  stmts.deleteEvent.run(req.params.id);
  res.json({ success: true });
});

// ── Registration routes ───────────────────────────────────────────

// Admin: all registrations
app.get('/api/registrations', requireAuth, (req, res) => {
  const { eventId } = req.query;
  const rows = eventId ? stmts.getRegsByEvent.all(eventId) : stmts.getRegs.all();
  res.json(rows.map(r => ({ ...r, event_name: r.event_name || '—', emoji: r.emoji || '🎉' })));
});

// User: only registrations for their own events
app.get('/api/registrations/mine', requireUser, (req, res) => {
  const { eventId } = req.query;
  let rows;
  if (eventId) {
    const ev = stmts.getEvent.get(eventId);
    if (!ev || ev.owner_id !== req.session.userId)
      return res.status(403).json({ error: 'Forbidden.' });
    rows = stmts.getRegsByEvent.all(eventId);
  } else {
    rows = stmts.getRegsByOwner.all(req.session.userId);
  }
  res.json(rows.map(r => ({ ...r, event_name: r.event_name || '—', emoji: r.emoji || '🎉' })));
});

app.post('/api/registrations', (req, res) => {
  const { eventId, name, phone } = req.body;
  if (!eventId || !name?.trim() || !phone?.trim())
    return res.status(400).json({ error: 'Missing required fields.' });
  if (!stmts.getEvent.get(eventId))
    return res.status(404).json({ error: 'Event not found.' });

  const id = crypto.randomUUID();
  stmts.insertReg.run(id, eventId, name.trim(), phone.trim(), new Date().toISOString());
  res.json({ success: true, id });
});

app.delete('/api/registrations/:id', requireAuthOrUser, (req, res) => {
  if (!req.session.authenticated) {
    const reg = stmts.getRegWithOwner.get(req.params.id);
    if (!reg || reg.owner_id !== req.session.userId)
      return res.status(403).json({ error: 'Forbidden.' });
  }
  stmts.deleteReg.run(req.params.id);
  res.json({ success: true });
});

app.delete('/api/events/:id/registrations', requireAuthOrUser, (req, res) => {
  const existing = stmts.getEvent.get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Event not found.' });
  if (!req.session.authenticated && existing.owner_id !== req.session.userId)
    return res.status(403).json({ error: 'Forbidden.' });
  stmts.deleteRegsByEvent.run(req.params.id);
  res.json({ success: true });
});

// ── Page routes ───────────────────────────────────────────────────
app.get('/event',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dashboard',  (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/admin',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
