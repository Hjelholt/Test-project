const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Credentials (change via environment variables in production) ──
const ADMIN_USER = process.env.ADMIN_USER || 'Admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret-in-production';

// ── Database setup ────────────────────────────────────────────────
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const db = new Database(path.join(dataDir, 'attendance.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS events (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    date      TEXT,
    emoji     TEXT NOT NULL DEFAULT '🎉',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS registrations (
    id         TEXT PRIMARY KEY,
    event_id   TEXT NOT NULL REFERENCES events(id),
    name       TEXT NOT NULL,
    phone      TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// ── Middleware ────────────────────────────────────────────────────
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
    maxAge: 8 * 60 * 60 * 1000 // 8 hours
  }
}));

// ── Auth middleware ───────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session.authenticated) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ── Auth routes ───────────────────────────────────────────────────
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

// ── Events ────────────────────────────────────────────────────────
app.get('/api/events', (req, res) => {
  const events = db.prepare('SELECT * FROM events ORDER BY date ASC, created_at DESC').all();
  res.json(events);
});

app.post('/api/events', requireAuth, (req, res) => {
  const { name, date, emoji } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Event name is required.' });

  const id = crypto.randomUUID();
  db.prepare('INSERT INTO events (id, name, date, emoji) VALUES (?, ?, ?, ?)')
    .run(id, name.trim(), date || null, emoji?.trim() || '🎉');

  res.json({ id, name: name.trim(), date: date || null, emoji: emoji?.trim() || '🎉' });
});

app.delete('/api/events/:id', requireAuth, (req, res) => {
  const del = db.transaction((id) => {
    db.prepare('DELETE FROM registrations WHERE event_id = ?').run(id);
    db.prepare('DELETE FROM events WHERE id = ?').run(id);
  });
  del(req.params.id);
  res.json({ success: true });
});

// ── Registrations ─────────────────────────────────────────────────
app.get('/api/registrations', requireAuth, (req, res) => {
  const { eventId } = req.query;
  const sql = `
    SELECT r.id, r.name, r.phone, r.created_at,
           e.id as event_id, e.name as event_name, e.emoji
    FROM registrations r
    LEFT JOIN events e ON r.event_id = e.id
    ${eventId ? 'WHERE r.event_id = ?' : ''}
    ORDER BY r.created_at DESC
  `;
  const regs = eventId
    ? db.prepare(sql).all(eventId)
    : db.prepare(sql).all();
  res.json(regs);
});

app.post('/api/registrations', (req, res) => {
  const { eventId, name, phone } = req.body;
  if (!eventId || !name?.trim() || !phone?.trim()) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }
  const event = db.prepare('SELECT id FROM events WHERE id = ?').get(eventId);
  if (!event) return res.status(404).json({ error: 'Event not found.' });

  const id = crypto.randomUUID();
  db.prepare('INSERT INTO registrations (id, event_id, name, phone) VALUES (?, ?, ?, ?)')
    .run(id, eventId, name.trim(), phone.trim());

  res.json({ success: true, id });
});

app.delete('/api/registrations/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM registrations WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

app.delete('/api/events/:id/registrations', requireAuth, (req, res) => {
  db.prepare('DELETE FROM registrations WHERE event_id = ?').run(req.params.id);
  res.json({ success: true });
});

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
