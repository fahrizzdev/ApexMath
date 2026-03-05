const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { questions, LEVELS, LEVEL_NAMES } = require('./questions');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'apexmath_dev_secret_change_in_prod';

// ── DATABASE SETUP ────────────────────────────────────────────────────────────
pool.query(`
  CREATE TABLE IF NOT EXISTS waitlist (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    level INTEGER DEFAULT 1,
    level_name TEXT DEFAULT 'Early Algebra',
    score INTEGER DEFAULT 0,
    total INTEGER DEFAULT 0,
    streak INTEGER DEFAULT 0,
    last_active DATE,
    created_at TIMESTAMP DEFAULT NOW()
  );
  CREATE TABLE IF NOT EXISTS diagnostic_results (
    id SERIAL PRIMARY KEY,
    email TEXT,
    level INTEGER,
    level_name TEXT,
    score INTEGER,
    total INTEGER,
    created_at TIMESTAMP DEFAULT NOW()
  );
`).then(() => console.log('Database ready')).catch(err => console.error('DB error:', err.message));

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── SESSIONS (for diagnostic) ─────────────────────────────────────────────────
const sessions = {};

// ── ROUTES ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// REGISTER
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Email already registered' });
    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, level, level_name, score, total, streak',
      [email, hash]
    );
    // Also add to waitlist
    await pool.query('INSERT INTO waitlist (email) VALUES ($1) ON CONFLICT (email) DO NOTHING', [email]);
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ success: true, token, user });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// LOGIN
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: 'No account found with that email' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: 'Incorrect password' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      success: true, token,
      user: { id: user.id, email: user.email, level: user.level, level_name: user.level_name, score: user.score, total: user.total, streak: user.streak }
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET CURRENT USER
app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, email, level, level_name, score, total, streak, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ user: result.rows[0] });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// WAITLIST (kept for backward compat)
app.post('/waitlist', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });
  try {
    await pool.query('INSERT INTO waitlist (email) VALUES ($1) ON CONFLICT (email) DO NOTHING', [email]);
    const result = await pool.query('SELECT COUNT(*) FROM waitlist');
    res.json({ success: true, count: parseInt(result.rows[0].count) });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/waitlist/count', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM waitlist');
    res.json({ count: parseInt(result.rows[0].count) });
  } catch {
    res.json({ count: 0 });
  }
});

// ADAPTIVE QUESTION
app.post('/question', (req, res) => {
  const { sessionId, currentLevel, correct, wrong } = req.body;
  if (!sessions[sessionId]) sessions[sessionId] = { seen: new Set(), level: currentLevel || 1 };
  const session = sessions[sessionId];
  if (correct > wrong + 1 && session.level < 6) session.level = Math.min(6, session.level + 1);
  else if (wrong > correct && session.level > 0) session.level = Math.max(0, session.level - 1);
  if (currentLevel !== undefined) session.level = currentLevel;
  const pool_q = questions[session.level];
  const unseen = pool_q.filter((_, i) => !session.seen.has(`${session.level}-${i}`));
  if (unseen.length === 0) {
    const tryLevel = session.level < 6 ? session.level + 1 : session.level - 1;
    const fallback = questions[tryLevel].filter((_, i) => !session.seen.has(`${tryLevel}-${i}`));
    if (fallback.length === 0) return res.json({ done: true });
    const idx = Math.floor(Math.random() * fallback.length);
    const origIdx = questions[tryLevel].indexOf(fallback[idx]);
    session.seen.add(`${tryLevel}-${origIdx}`);
    return res.json({ question: fallback[idx], level: tryLevel, levelName: LEVEL_NAMES[tryLevel], done: false });
  }
  const idx = Math.floor(Math.random() * unseen.length);
  const origIdx = pool_q.indexOf(unseen[idx]);
  session.seen.add(`${session.level}-${origIdx}`);
  res.json({ question: unseen[idx], level: session.level, levelName: LEVEL_NAMES[session.level], done: false });
});

// SAVE RESULT + update user if logged in
app.post('/result', async (req, res) => {
  const { email, level, levelName, score, total } = req.body;
  try {
    await pool.query(
      'INSERT INTO diagnostic_results (email, level, level_name, score, total) VALUES ($1,$2,$3,$4,$5)',
      [email || null, level, levelName, score, total]
    );
    // Update user level if they have an account
    if (email) {
      await pool.query(
        'UPDATE users SET level=$1, level_name=$2, score=$3, total=$4, last_active=CURRENT_DATE WHERE email=$5',
        [level, levelName, score, total, email]
      );
    }
  } catch {}
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Apex Math running on port ${PORT}`));
