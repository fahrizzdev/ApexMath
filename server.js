const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const { questions, LEVELS, LEVEL_NAMES, TOPIC_LESSON_MAP } = require('./questions');
const crypto = require('crypto');

// ── Auth helpers ─────────────────────────────────────────────────────────────
function hashPassword(password, salt) {
  if (!salt) salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt };
}
function verifyPassword(password, salt, storedHash) {
  return hashPassword(password, salt).hash === storedHash;
}
function makeToken(userId) {
  const payload = Buffer.from(JSON.stringify({ userId, iat: Date.now() })).toString('base64');
  const sig = crypto.createHmac('sha256', process.env.JWT_SECRET || 'scalar-dev-secret')
    .update(payload).digest('hex');
  return `${payload}.${sig}`;
}
function verifyToken(token) {
  if (!token) return null;
  const [payload, sig] = token.split('.');
  if (!payload || !sig) return null;
  const expected = crypto.createHmac('sha256', process.env.JWT_SECRET || 'scalar-dev-secret')
    .update(payload).digest('hex');
  if (expected !== sig) return null;
  try { return JSON.parse(Buffer.from(payload, 'base64').toString()); } catch { return null; }
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
  ssl: { rejectUnauthorized: false }
});

// ── DB init ───────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
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
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS waitlist (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS diagnostic_results (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      email TEXT,
      level INTEGER,
      level_name TEXT,
      score INTEGER,
      total INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // DB-backed question sessions (replaces in-memory sessions that reset on restart)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS question_sessions (
      session_id TEXT PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      seen_keys TEXT[] DEFAULT '{}',
      current_level INTEGER DEFAULT 1,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Per-topic mastery tracking (replaces localStorage-only weak spots)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS topic_performance (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      topic TEXT NOT NULL,
      correct_count INTEGER DEFAULT 0,
      wrong_count INTEGER DEFAULT 0,
      last_seen TIMESTAMP DEFAULT NOW(),
      UNIQUE(user_id, topic)
    )
  `);

  // Daily quiz results (tracks per-question outcomes)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS daily_quiz_results (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      quiz_date DATE NOT NULL,
      score INTEGER NOT NULL,
      total INTEGER NOT NULL,
      passed BOOLEAN NOT NULL,
      topic_results JSONB DEFAULT '[]',
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Notes: synced to DB (replaces localStorage-only notes)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_notes (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      level INTEGER NOT NULL,
      content TEXT DEFAULT '',
      updated_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY(user_id, level)
    )
  `);

  // Study sessions (timer): synced to DB
  await pool.query(`
    CREATE TABLE IF NOT EXISTS study_sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      duration_ms INTEGER NOT NULL,
      session_date DATE NOT NULL DEFAULT CURRENT_DATE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  console.log('Database ready');
}
initDB().catch(err => console.error('DB init error:', err.message));

// ── Static routes ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// ── Waitlist ──────────────────────────────────────────────────────────────────
app.post('/waitlist', async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Invalid email' });
  try {
    await pool.query('INSERT INTO waitlist (email) VALUES ($1) ON CONFLICT (email) DO NOTHING', [email]);
    const result = await pool.query('SELECT COUNT(*) FROM waitlist');
    res.json({ success: true, count: parseInt(result.rows[0].count) });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.get('/waitlist/count', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM waitlist');
    res.json({ count: parseInt(result.rows[0].count) });
  } catch { res.json({ count: 0 }); }
});

// ── Adaptive question (DB-backed session) ────────────────────────────────────
app.post('/question', async (req, res) => {
  const { sessionId, currentLevel, correct, wrong, userId } = req.body;

  try {
    // Load or create session from DB
    let session = null;
    const existing = await pool.query(
      'SELECT * FROM question_sessions WHERE session_id = $1', [sessionId]
    );

    if (existing.rows.length === 0) {
      await pool.query(
        'INSERT INTO question_sessions (session_id, user_id, current_level) VALUES ($1, $2, $3)',
        [sessionId, userId || null, currentLevel || 1]
      );
      session = { seen_keys: [], current_level: currentLevel || 1 };
    } else {
      session = existing.rows[0];
    }

    let level = session.current_level;

    // Override if explicit level sent
    if (currentLevel !== undefined) level = currentLevel;

    // Adjust level based on performance
    if (correct > wrong + 1 && level < 6) level = Math.min(6, level + 1);
    else if (wrong > correct && level > 0) level = Math.max(0, level - 1);

    const seenSet = new Set(session.seen_keys || []);
    const pool_q = questions[level];
    const unseen = pool_q.filter((_, i) => !seenSet.has(`${level}-${i}`));

    if (unseen.length === 0) {
      const tryLevel = level < 6 ? level + 1 : level - 1;
      const fallback = questions[tryLevel].filter((_, i) => !seenSet.has(`${tryLevel}-${i}`));
      if (fallback.length === 0) return res.json({ done: true });
      const idx = Math.floor(Math.random() * fallback.length);
      const origIdx = questions[tryLevel].indexOf(fallback[idx]);
      const newKey = `${tryLevel}-${origIdx}`;
      await pool.query(
        'UPDATE question_sessions SET seen_keys = seen_keys || $1::text, current_level = $2, updated_at = NOW() WHERE session_id = $3',
        [newKey, tryLevel, sessionId]
      );
      return res.json({ question: fallback[idx], level: tryLevel, levelName: LEVEL_NAMES[tryLevel], done: false });
    }

    const idx = Math.floor(Math.random() * unseen.length);
    const origIdx = pool_q.indexOf(unseen[idx]);
    const newKey = `${level}-${origIdx}`;
    await pool.query(
      'UPDATE question_sessions SET seen_keys = seen_keys || $1::text, current_level = $2, updated_at = NOW() WHERE session_id = $3',
      [newKey, level, sessionId]
    );

    res.json({ question: unseen[idx], level, levelName: LEVEL_NAMES[level], done: false });
  } catch (err) {
    console.error('Question error:', err.message);
    // Fallback to in-memory if DB fails
    const level = currentLevel || 1;
    const pool_q = questions[level];
    const q = pool_q[Math.floor(Math.random() * pool_q.length)];
    res.json({ question: q, level, levelName: LEVEL_NAMES[level], done: false });
  }
});

// ── Save diagnostic result → auto-update user level ─────────────────────────
app.post('/result', async (req, res) => {
  const { email, level, levelName, score, total, userId } = req.body;
  try {
    // Save result
    await pool.query(
      'INSERT INTO diagnostic_results (user_id, email, level, level_name, score, total) VALUES ($1,$2,$3,$4,$5,$6)',
      [userId || null, email || null, level, levelName, score, total]
    );
    // Auto-update user's level if they're logged in
    if (userId) {
      await pool.query('UPDATE users SET level = $1 WHERE id = $2', [level, userId]);
    }
  } catch (err) { console.error('Result save error:', err.message); }
  res.json({ success: true });
});

// ── Topic performance ─────────────────────────────────────────────────────────
app.post('/track-answer', authMiddleware, async (req, res) => {
  const { topic, correct } = req.body;
  if (!topic) return res.json({ ok: true });
  try {
    if (correct) {
      await pool.query(`
        INSERT INTO topic_performance (user_id, topic, correct_count)
        VALUES ($1, $2, 1)
        ON CONFLICT (user_id, topic) DO UPDATE
        SET correct_count = topic_performance.correct_count + 1, last_seen = NOW()
      `, [req.userId, topic]);
    } else {
      await pool.query(`
        INSERT INTO topic_performance (user_id, topic, wrong_count)
        VALUES ($1, $2, 1)
        ON CONFLICT (user_id, topic) DO UPDATE
        SET wrong_count = topic_performance.wrong_count + 1, last_seen = NOW()
      `, [req.userId, topic]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('Track answer error:', err.message);
    res.json({ ok: false });
  }
});

app.get('/topic-performance', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT topic, correct_count, wrong_count, last_seen FROM topic_performance WHERE user_id = $1 ORDER BY wrong_count DESC',
      [req.userId]
    );
    // Attach lesson links
    const rows = result.rows.map(r => ({
      ...r,
      lesson: TOPIC_LESSON_MAP[r.topic] || null
    }));
    res.json({ topics: rows });
  } catch {
    res.json({ topics: [] });
  }
});

// ── Auth routes ───────────────────────────────────────────────────────────────
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
    res.json({ token, email: result.rows[0].email, level: 0, levelName: LEVEL_NAMES[0], streak: 0, userId: result.rows[0].id });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: 'Server error' });
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
    res.json({ token, email: user.email, level: user.level || 0, levelName: LEVEL_NAMES[user.level || 0], streak: user.streak || 0, userId: user.id });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.get('/auth/me', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, level, streak, last_quiz_date FROM users WHERE id=$1', [req.userId]);
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    const u = result.rows[0];
    res.json({ email: u.email, level: u.level || 0, levelName: LEVEL_NAMES[u.level || 0], streak: u.streak || 0, lastQuizDate: u.last_quiz_date, userId: u.id });
  } catch { res.status(500).json({ error: 'Server error' }); }
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
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/auth/update-level', authMiddleware, async (req, res) => {
  const { level } = req.body;
  if (level === undefined || level < 0 || level > 6) return res.status(400).json({ error: 'Invalid level' });
  try {
    await pool.query('UPDATE users SET level=$1 WHERE id=$2', [level, req.userId]);
    res.json({ success: true, level, levelName: LEVEL_NAMES[level] });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/auth/reset-streak', authMiddleware, async (req, res) => {
  try {
    await pool.query('UPDATE users SET streak=0, last_quiz_date=NULL WHERE id=$1', [req.userId]);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ── Dashboard ─────────────────────────────────────────────────────────────────
app.get('/dashboard', authMiddleware, async (req, res) => {
  try {
    const [userRes, topicRes, weekRes, studyRes] = await Promise.all([
      pool.query('SELECT id, email, level, streak, last_quiz_date FROM users WHERE id=$1', [req.userId]),
      pool.query('SELECT topic, correct_count, wrong_count FROM topic_performance WHERE user_id=$1', [req.userId]),
      pool.query(`
        SELECT quiz_date, score, total, passed FROM daily_quiz_results
        WHERE user_id=$1 AND quiz_date >= CURRENT_DATE - INTERVAL '7 days'
        ORDER BY quiz_date DESC
      `, [req.userId]),
      pool.query(`
        SELECT COALESCE(SUM(duration_ms), 0) as total_ms FROM study_sessions
        WHERE user_id=$1 AND session_date >= CURRENT_DATE - INTERVAL '7 days'
      `, [req.userId])
    ]);

    if (!userRes.rows[0]) return res.status(404).json({ error: 'User not found' });
    const u = userRes.rows[0];
    const today = new Date().toISOString().split('T')[0];
    const todayResult = weekRes.rows.find(r => r.quiz_date.toISOString().split('T')[0] === today);
    const completedToday = !!todayResult;
    const passedToday = todayResult?.passed || false;
    const totalQuizzes = await pool.query('SELECT COUNT(*) FROM daily_quiz_results WHERE user_id=$1', [req.userId]);

    // Weak spots from DB
    const weakTopics = topicRes.rows
      .filter(t => t.wrong_count > 0)
      .sort((a, b) => b.wrong_count - a.wrong_count)
      .slice(0, 10)
      .map(t => ({
        topic: t.topic,
        wrong: t.wrong_count,
        correct: t.correct_count,
        lesson: TOPIC_LESSON_MAP[t.topic] || null
      }));

    // Week days for streak calendar
    const weekDays = [];
    for (let i = 6; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000);
      const ds = d.toISOString().split('T')[0];
      const result = weekRes.rows.find(r => r.quiz_date.toISOString().split('T')[0] === ds);
      weekDays.push({ date: ds, done: !!result, passed: result?.passed || false });
    }

    res.json({
      user: { email: u.email, level: u.level || 0, level_name: LEVEL_NAMES[u.level || 0] },
      streak: u.streak || 0,
      completedToday,
      passedToday,
      totalQuizzes: parseInt(totalQuizzes.rows[0].count),
      weekDays,
      weakTopics,
      studyMsThisWeek: parseInt(studyRes.rows[0]?.total_ms || 0),
    });
  } catch (err) {
    console.error('Dashboard error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Daily quiz ────────────────────────────────────────────────────────────────
app.get('/daily/questions', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query('SELECT level FROM users WHERE id=$1', [req.userId]);
    const level = result.rows[0]?.level || 0;

    // Pull 5 questions, biased toward weak topics
    const topicPerf = await pool.query(
      'SELECT topic, wrong_count FROM topic_performance WHERE user_id=$1 ORDER BY wrong_count DESC LIMIT 5',
      [req.userId]
    );
    const weakTopics = new Set(topicPerf.rows.map(r => r.topic));

    const pool_q = questions[level];
    // Weight weak-topic questions 3x
    const weighted = pool_q.flatMap(q =>
      weakTopics.has(q.topic) ? [q, q, q] : [q]
    );
    const shuffled = [...weighted].sort(() => Math.random() - 0.5);
    // Deduplicate
    const seen = new Set();
    const selected = [];
    for (const q of shuffled) {
      const key = q.q;
      if (!seen.has(key)) { seen.add(key); selected.push(q); }
      if (selected.length >= 5) break;
    }
    // Pad if needed
    if (selected.length < 5) {
      const remaining = pool_q.filter(q => !selected.includes(q)).sort(() => Math.random() - 0.5);
      selected.push(...remaining.slice(0, 5 - selected.length));
    }

    res.json({ questions: selected.slice(0, 5), level, levelName: LEVEL_NAMES[level] });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/daily/complete', authMiddleware, async (req, res) => {
  const { score, topicResults } = req.body;
  // topicResults: [{ topic, correct: bool }]
  try {
    const result = await pool.query('SELECT streak, last_quiz_date FROM users WHERE id=$1', [req.userId]);
    const u = result.rows[0];
    const today = new Date().toISOString().split('T')[0];
    const lastDate = u.last_quiz_date ? u.last_quiz_date.toISOString().split('T')[0] : null;
    const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];

    let newStreak = 1;
    if (lastDate === yesterday) newStreak = (u.streak || 0) + 1;
    else if (lastDate === today) newStreak = u.streak || 1;

    const passed = score >= 3;
    await pool.query('UPDATE users SET streak=$1, last_quiz_date=NOW() WHERE id=$2', [newStreak, req.userId]);

    // Record quiz result
    await pool.query(
      'INSERT INTO daily_quiz_results (user_id, quiz_date, score, total, passed, topic_results) VALUES ($1, CURRENT_DATE, $2, 5, $3, $4) ON CONFLICT DO NOTHING',
      [req.userId, score, passed, JSON.stringify(topicResults || [])]
    );

    // Update topic performance for each answered question
    if (Array.isArray(topicResults)) {
      for (const tr of topicResults) {
        if (!tr.topic) continue;
        if (tr.correct) {
          await pool.query(`
            INSERT INTO topic_performance (user_id, topic, correct_count)
            VALUES ($1, $2, 1)
            ON CONFLICT (user_id, topic) DO UPDATE
            SET correct_count = topic_performance.correct_count + 1, last_seen = NOW()
          `, [req.userId, tr.topic]);
        } else {
          await pool.query(`
            INSERT INTO topic_performance (user_id, topic, wrong_count)
            VALUES ($1, $2, 1)
            ON CONFLICT (user_id, topic) DO UPDATE
            SET wrong_count = topic_performance.wrong_count + 1, last_seen = NOW()
          `, [req.userId, tr.topic]);
        }
      }
    }

    res.json({ success: true, streak: newStreak, passed });
  } catch (err) {
    console.error('Daily complete error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Notes (synced to DB) ──────────────────────────────────────────────────────
app.get('/notes/:level', authMiddleware, async (req, res) => {
  const level = parseInt(req.params.level);
  if (isNaN(level) || level < 0 || level > 6) return res.status(400).json({ error: 'Invalid level' });
  try {
    const result = await pool.query(
      'SELECT content, updated_at FROM user_notes WHERE user_id=$1 AND level=$2',
      [req.userId, level]
    );
    res.json({ content: result.rows[0]?.content || '', updatedAt: result.rows[0]?.updated_at || null });
  } catch { res.json({ content: '' }); }
});

app.post('/notes/:level', authMiddleware, async (req, res) => {
  const level = parseInt(req.params.level);
  if (isNaN(level) || level < 0 || level > 6) return res.status(400).json({ error: 'Invalid level' });
  const { content } = req.body;
  try {
    await pool.query(`
      INSERT INTO user_notes (user_id, level, content, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (user_id, level) DO UPDATE SET content=$3, updated_at=NOW()
    `, [req.userId, level, content || '']);
    res.json({ success: true });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

// ── Study timer (synced to DB) ────────────────────────────────────────────────
app.post('/study-session', authMiddleware, async (req, res) => {
  const { durationMs } = req.body;
  if (!durationMs || durationMs < 10000) return res.json({ ok: true }); // ignore < 10s
  try {
    await pool.query(
      'INSERT INTO study_sessions (user_id, duration_ms) VALUES ($1, $2)',
      [req.userId, Math.floor(durationMs)]
    );
    res.json({ ok: true });
  } catch { res.json({ ok: false }); }
});

app.get('/study-sessions', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT session_date, SUM(duration_ms) as total_ms
      FROM study_sessions WHERE user_id=$1 AND session_date >= CURRENT_DATE - INTERVAL '30 days'
      GROUP BY session_date ORDER BY session_date DESC
    `, [req.userId]);
    const weekTotal = await pool.query(`
      SELECT COALESCE(SUM(duration_ms), 0) as ms
      FROM study_sessions WHERE user_id=$1 AND session_date >= CURRENT_DATE - INTERVAL '7 days'
    `, [req.userId]);
    res.json({
      sessions: result.rows,
      weekTotalMs: parseInt(weekTotal.rows[0]?.ms || 0)
    });
  } catch { res.json({ sessions: [], weekTotalMs: 0 }); }
});

// ── Topic lesson link endpoint ────────────────────────────────────────────────
app.get('/topic-lesson/:topic', (req, res) => {
  const lesson = TOPIC_LESSON_MAP[decodeURIComponent(req.params.topic)];
  if (!lesson) return res.json({ found: false });
  res.json({ found: true, ...lesson });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Scalar running on port ${PORT}`));
