const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Credentials (override via environment variables in production) ──
const ADMIN_USER = process.env.ADMIN_USER || 'Admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret-in-production';

// ── SQLite database (set DATA_DIR to a persistent volume path) ───
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'app.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
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

// ── Prepared statements ──────────────────────────────────────────
const stmts = {
  getEvents:        db.prepare("SELECT * FROM events ORDER BY COALESCE(date, '9999') ASC"),
  getEvent:         db.prepare('SELECT * FROM events WHERE id = ?'),
  insertEvent:      db.prepare('INSERT INTO events (id, name, date, time, location, emoji, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'),
  updateEvent:      db.prepare('UPDATE events SET name = ?, date = ?, time = ?, location = ?, emoji = ? WHERE id = ?'),
  deleteEvent:      db.prepare('DELETE FROM events WHERE id = ?'),
  getRegs:          db.prepare(`SELECT r.*, e.name AS event_name, e.emoji FROM registrations r LEFT JOIN events e ON r.event_id = e.id ORDER BY r.created_at DESC`),
  getRegsByEvent:   db.prepare(`SELECT r.*, e.name AS event_name, e.emoji FROM registrations r LEFT JOIN events e ON r.event_id = e.id WHERE r.event_id = ? ORDER BY r.created_at DESC`),
  insertReg:        db.prepare('INSERT INTO registrations (id, event_id, name, phone, created_at) VALUES (?, ?, ?, ?, ?)'),
  deleteReg:        db.prepare('DELETE FROM registrations WHERE id = ?'),
  deleteRegsByEvent: db.prepare('DELETE FROM registrations WHERE event_id = ?'),
};

// ── Events ────────────────────────────────────────────────────────
app.get('/api/events', (req, res) => {
  res.json(stmts.getEvents.all());
});

app.post('/api/events', requireAuth, (req, res) => {
  const { name, date, time, location, emoji } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Event name is required.' });

  const event = {
    id: crypto.randomUUID(),
    name: name.trim(),
    date: date || null,
    time: time || null,
    location: location?.trim() || null,
    emoji: emoji?.trim() || '🎉',
    created_at: new Date().toISOString()
  };
  stmts.insertEvent.run(event.id, event.name, event.date, event.time, event.location, event.emoji, event.created_at);
  res.json(event);
});

app.put('/api/events/:id', requireAuth, (req, res) => {
  const { name, date, time, location, emoji } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Event name is required.' });

  const existing = stmts.getEvent.get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Event not found.' });

  stmts.updateEvent.run(name.trim(), date || null, time || null, location?.trim() || null, emoji?.trim() || '🎉', req.params.id);
  res.json({ ...existing, name: name.trim(), date: date || null, time: time || null, location: location?.trim() || null, emoji: emoji?.trim() || '🎉' });
});

app.delete('/api/events/:id', requireAuth, (req, res) => {
  stmts.deleteEvent.run(req.params.id); // CASCADE deletes registrations
  res.json({ success: true });
});

// ── Registrations ─────────────────────────────────────────────────
app.get('/api/registrations', requireAuth, (req, res) => {
  const { eventId } = req.query;
  const rows = eventId ? stmts.getRegsByEvent.all(eventId) : stmts.getRegs.all();
  res.json(rows.map(r => ({ ...r, event_name: r.event_name || '—', emoji: r.emoji || '🎉' })));
});

app.post('/api/registrations', (req, res) => {
  const { eventId, name, phone } = req.body;
  if (!eventId || !name?.trim() || !phone?.trim()) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  if (!stmts.getEvent.get(eventId)) {
    return res.status(404).json({ error: 'Event not found.' });
  }

  const id = crypto.randomUUID();
  stmts.insertReg.run(id, eventId, name.trim(), phone.trim(), new Date().toISOString());
  res.json({ success: true, id });
});

app.delete('/api/registrations/:id', requireAuth, (req, res) => {
  stmts.deleteReg.run(req.params.id);
  res.json({ success: true });
});

app.delete('/api/events/:id/registrations', requireAuth, (req, res) => {
  stmts.deleteRegsByEvent.run(req.params.id);
  res.json({ success: true });
});

// ── HTML pages ──────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
