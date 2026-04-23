const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Credentials (override via environment variables in production) ──
const ADMIN_USER = process.env.ADMIN_USER || 'Admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin';
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret-in-production';

// ── JSON file store ───────────────────────────────────────────────
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir);

const EVENTS_FILE = path.join(dataDir, 'events.json');
const REGS_FILE   = path.join(dataDir, 'registrations.json');

function readJSON(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return []; }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8');
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
  const events = readJSON(EVENTS_FILE);
  // Sort by date ascending, then by creation order
  events.sort((a, b) => (a.date || '9999') < (b.date || '9999') ? -1 : 1);
  res.json(events);
});

app.post('/api/events', requireAuth, (req, res) => {
  const { name, date, time, location, emoji } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Event name is required.' });

  const events = readJSON(EVENTS_FILE);
  const event = {
    id: crypto.randomUUID(),
    name: name.trim(),
    date: date || null,
    time: time || null,
    location: location?.trim() || null,
    emoji: emoji?.trim() || '🎉',
    created_at: new Date().toISOString()
  };
  events.push(event);
  writeJSON(EVENTS_FILE, events);
  res.json(event);
});

app.put('/api/events/:id', requireAuth, (req, res) => {
  const { name, date, time, location, emoji } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Event name is required.' });

  const events = readJSON(EVENTS_FILE);
  const idx = events.findIndex(e => e.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Event not found.' });

  events[idx] = {
    ...events[idx],
    name: name.trim(),
    date: date || null,
    time: time || null,
    location: location?.trim() || null,
    emoji: emoji?.trim() || '🎉'
  };
  writeJSON(EVENTS_FILE, events);
  res.json(events[idx]);
});

app.delete('/api/events/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  writeJSON(EVENTS_FILE, readJSON(EVENTS_FILE).filter(e => e.id !== id));
  writeJSON(REGS_FILE,   readJSON(REGS_FILE).filter(r => r.event_id !== id));
  res.json({ success: true });
});

// ── Registrations ─────────────────────────────────────────────────
app.get('/api/registrations', requireAuth, (req, res) => {
  const { eventId } = req.query;
  const events = readJSON(EVENTS_FILE);
  const evMap  = Object.fromEntries(events.map(e => [e.id, e]));

  let regs = readJSON(REGS_FILE);
  if (eventId) regs = regs.filter(r => r.event_id === eventId);

  // Sort newest first and attach event info
  regs.sort((a, b) => b.created_at.localeCompare(a.created_at));
  const result = regs.map(r => ({
    ...r,
    event_name: evMap[r.event_id]?.name || '—',
    emoji:      evMap[r.event_id]?.emoji || '🎉'
  }));

  res.json(result);
});

app.post('/api/registrations', (req, res) => {
  const { eventId, name, phone } = req.body;
  if (!eventId || !name?.trim() || !phone?.trim()) {
    return res.status(400).json({ error: 'Missing required fields.' });
  }

  const events = readJSON(EVENTS_FILE);
  if (!events.find(e => e.id === eventId)) {
    return res.status(404).json({ error: 'Event not found.' });
  }

  const regs = readJSON(REGS_FILE);
  const reg = {
    id: crypto.randomUUID(),
    event_id: eventId,
    name: name.trim(),
    phone: phone.trim(),
    created_at: new Date().toISOString()
  };
  regs.push(reg);
  writeJSON(REGS_FILE, regs);
  res.json({ success: true, id: reg.id });
});

app.delete('/api/registrations/:id', requireAuth, (req, res) => {
  writeJSON(REGS_FILE, readJSON(REGS_FILE).filter(r => r.id !== req.params.id));
  res.json({ success: true });
});

app.delete('/api/events/:id/registrations', requireAuth, (req, res) => {
  writeJSON(REGS_FILE, readJSON(REGS_FILE).filter(r => r.event_id !== req.params.id));
  res.json({ success: true });
});

// ── Start ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
