const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const { questions, LEVELS, LEVEL_NAMES } = require('./questions');
const crypto = require('crypto');

// ── Auth helpers (no external deps) ──────────────────────────────────────────
function hashPassword(password, salt) {
  if (!salt) salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt };
}
function verifyPassword(password, salt, storedHash) {
  const { hash } = hashPassword(password, salt);
  return hash === storedHash;
}
function makeToken(userId) {
  // Use base64url (no dots) so we can safely split on '|'
  const payload = Buffer.from(JSON.stringify({ userId, iat: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.JWT_SECRET || 'scalar-dev-secret')
    .update(payload).digest('hex');
  return `${payload}|${sig}`;
}
function verifyToken(token) {
  if (!token) return null;
  const lastPipe = token.lastIndexOf('|');
  if (lastPipe === -1) return null;
  const payload = token.slice(0, lastPipe);
  const sig = token.slice(lastPipe + 1);
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', process.env.JWT_SECRET || 'scalar-dev-secret')
    .update(payload).digest('hex');
  if (expected !== sig) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64url').toString()); } catch { return null; }
}
function authMiddleware(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ error: 'Unauthorized' });
  req.userId = decoded.userId;
  next();
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ── DB init ───────────────────────────────────────────────────────────────────
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    level INTEGER DEFAULT 0,
    streak INTEGER DEFAULT 0,
    last_quiz_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
  )
`).catch(err => console.error('Users table error:', err.message));

Promise.all([
  pool.query(`
    CREATE TABLE IF NOT EXISTS waitlist (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `),
  pool.query(`
    CREATE TABLE IF NOT EXISTS diagnostic_results (
      id SERIAL PRIMARY KEY,
      email TEXT,
      level INTEGER,
      level_name TEXT,
      score INTEGER,
      total INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `)
]).then(() => console.log('Database ready')).catch(err => console.error('DB error:', err.message));

// Track seen questions per session (in-memory, keyed by session token)
const sessions = {};

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

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

// Get next adaptive question
app.post('/question', (req, res) => {
  const { sessionId, currentLevel, correct, wrong } = req.body;

  if (!sessions[sessionId]) sessions[sessionId] = { seen: new Set(), level: currentLevel || 1 };
  const session = sessions[sessionId];

  // Adjust level based on performance
  if (correct > wrong + 1 && session.level < 6) session.level = Math.min(6, session.level + 1);
  else if (wrong > correct && session.level > 0) session.level = Math.max(0, session.level - 1);

  // If currentLevel override sent, use it
  if (currentLevel !== undefined) session.level = currentLevel;

  // Get unseen questions for current level
  const pool_q = questions[session.level];
  const unseen = pool_q.filter((_, i) => !session.seen.has(`${session.level}-${i}`));

  if (unseen.length === 0) {
    // Try adjacent levels
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

// Save result
app.post('/result', async (req, res) => {
  const { email, level, levelName, score, total } = req.body;
  try {
    await pool.query(
      'INSERT INTO diagnostic_results (email, level, level_name, score, total) VALUES ($1,$2,$3,$4,$5)',
      [email || null, level, levelName, score, total]
    );
  } catch {}
  res.json({ success: true });
});

// ── Auth routes ──────────────────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password too short (min 6 chars)' });
  try {
    const { hash, salt } = hashPassword(password);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash, password_salt) VALUES ($1,$2,$3) RETURNING id, email',
      [email.toLowerCase().trim(), hash, salt]
    );
    const token = makeToken(result.rows[0].id);
    res.json({ token, email: result.rows[0].email, level: 0, levelName: LEVEL_NAMES[0], streak: 0 });
  } catch (err) {
    console.error('Register error:', err.message);
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    const user = result.rows[0];
    if (!user || !verifyPassword(password, user.password_salt, user.password_hash))
      return res.status(401).json({ error: 'Invalid email or password' });
    const token = makeToken(user.id);
    res.json({ token, email: user.email, level: user.level || 0, levelName: LEVEL_NAMES[user.level || 0], streak: user.streak || 0 });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, level, streak, last_quiz_date FROM users WHERE id=$1', [req.userId]);
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    const level = u.level || 0;
    res.json({
      user: { email: u.email, level, level_name: LEVEL_NAMES[level] },
      streak: u.streak || 0
    });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both fields required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password too short' });
  try {
    const result = await pool.query('SELECT * FROM users WHERE id=$1', [req.userId]);
    const user = result.rows[0];
    if (!user || !verifyPassword(currentPassword, user.password_salt, user.password_hash))
      return res.status(401).json({ error: 'Current password is incorrect' });
    const { hash, salt } = hashPassword(newPassword);
    await pool.query('UPDATE users SET password_hash=$1, password_salt=$2 WHERE id=$3', [hash, salt, req.userId]);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/update-level', authMiddleware, async (req, res) => {
  const { level } = req.body;
  if (level === undefined || level < 0 || level > 6) return res.status(400).json({ error: 'Invalid level' });
  try {
    await pool.query('UPDATE users SET level=$1 WHERE id=$2', [level, req.userId]);
    res.json({ success: true, level, levelName: LEVEL_NAMES[level] });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/reset-streak', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE users SET streak=0, last_quiz_date=NULL WHERE id=$1', [req.userId]);
    res.json({ success: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Dashboard route ───────────────────────────────────────────────────────────
app.get('/dashboard', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT email, level, streak, last_quiz_date FROM users WHERE id=$1', [req.userId]);
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    const level = u.level || 0;
    const streak = u.streak || 0;
    const today = new Date().toISOString().split('T')[0];
    const lastDate = u.last_quiz_date ? new Date(u.last_quiz_date).toISOString().split('T')[0] : null;
    const completedToday = lastDate === today;

    // Build a 7-day strip: true if that day had a quiz session within current streak
    const weekDays = Array.from({ length: 7 }, (_, i) => {
      const d = new Date(); d.setDate(d.getDate() - (6 - i));
      const ds = d.toISOString().split('T')[0];
      // Mark as done if it falls within the current streak window
      const daysAgo = 6 - i;
      return { date: ds, done: completedToday ? daysAgo < streak : daysAgo < streak - 1 && streak > 0 };
    });

    res.json({
      user: { email: u.email, level, level_name: LEVEL_NAMES[level] },
      streak,
      completedToday,
      passedToday: completedToday,
      totalQuizzes: streak,
      weekDays
    });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Daily quiz routes ─────────────────────────────────────────────────────────
app.get('/daily/questions', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT level FROM users WHERE id=$1', [req.userId]);
    const level = result.rows[0]?.level || 0;
    const pool_q = questions[level];
    const shuffled = [...pool_q].sort(() => Math.random() - 0.5).slice(0, 5);
    res.json({ questions: shuffled, level, levelName: LEVEL_NAMES[level] });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/daily/complete', authMiddleware, async (req, res) => {
  const { score } = req.body;
  try {
    const result = await pool.query('SELECT streak, last_quiz_date FROM users WHERE id=$1', [req.userId]);
    const u = result.rows[0];
    const today = new Date().toISOString().split('T')[0];
    const lastDate = u.last_quiz_date ? u.last_quiz_date.toISOString().split('T')[0] : null;
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
    let newStreak = 1;
    if (lastDate === yesterday) newStreak = (u.streak || 0) + 1;
    else if (lastDate === today) newStreak = u.streak || 1;
    await pool.query('UPDATE users SET streak=$1, last_quiz_date=NOW() WHERE id=$2', [newStreak, req.userId]);
    res.json({ success: true, streak: newStreak });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Apex Math running on port ${PORT}`));
