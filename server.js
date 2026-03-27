require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');

const { pool } = require('./db/pool');
const { apiLimiter } = require('./middleware/rateLimit');
const { errorHandler, initSentry, sentryErrorHandler } = require('./middleware/errorHandler');
const { validate } = require('./middleware/validate');
const { LEVEL_NAMES } = require('./data/questions');

// Routes
const authRoutes      = require('./routes/auth');
const questionRoutes  = require('./routes/questions');
const dailyRoutes     = require('./routes/daily');
const dashboardRoutes = require('./routes/dashboard');
const notesRoutes     = require('./routes/notes');
const studyRoutes     = require('./routes/study');
const topicsRoutes    = require('./routes/topics');
const waitlistRoutes  = require('./routes/waitlist');

const app = express();

// ── Sentry (must be first) ─────────────────────────────────────────────────────
initSentry(app);

// ── Security headers ──────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for now — KaTeX + inline scripts need it tuned
}));

// ── CORS — only allow your actual domain ──────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(o => o.trim())
  .filter(Boolean);

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, Postman)
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.length === 0) {
      // No origins configured — dev mode, allow all (log a warning)
      console.warn('WARNING: ALLOWED_ORIGINS not set. CORS is open — do not deploy this way.');
      return callback(null, true);
    }
    if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: origin ${origin} not allowed`));
  },
  credentials: true,
}));

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '100kb' }));

// ── General API rate limit ────────────────────────────────────────────────────
app.use('/api/', apiLimiter);

// ── Static files — /public only, NOT the whole project directory ──────────────
app.use(express.static(path.join(__dirname, '..', 'public')));

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api/auth',       authRoutes);
app.use('/api/question',   questionRoutes);
app.use('/api/daily',      dailyRoutes);
app.use('/api/dashboard',  dashboardRoutes);
app.use('/api/notes',      notesRoutes);
app.use('/api/study-session', studyRoutes);
app.use('/api/topics',     topicsRoutes);
app.use('/api/waitlist',   waitlistRoutes);

// Diagnostic result save (kept at top level for simplicity)
app.post('/api/result', validate('result'), async (req, res, next) => {
  const { email, level, levelName, score, total, userId } = req.body;
  try {
    await pool.query(
      'INSERT INTO diagnostic_results (user_id, email, level, level_name, score, total) VALUES ($1,$2,$3,$4,$5,$6)',
      [userId || null, email || null, level, levelName, score, total]
    );
    if (userId) {
      await pool.query('UPDATE users SET level=$1 WHERE id=$2', [level, userId]);
    }
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// ── SPA fallback — serve index.html for all unmatched GET routes ──────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ── Error handling (must be last) ─────────────────────────────────────────────
app.use(sentryErrorHandler());
app.use(errorHandler);

// ── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Scalar running on port ${PORT}`);
  console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
  if (!process.env.JWT_SECRET) {
    console.error('⚠️  WARNING: JWT_SECRET not set!');
  }
});
