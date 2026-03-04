const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const { questions, LEVELS, LEVEL_NAMES } = require('./questions');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

pool.query(`
  CREATE TABLE IF NOT EXISTS waitlist (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Apex Math running on port ${PORT}`));
