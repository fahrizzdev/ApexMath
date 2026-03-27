const { Router } = require('express');
const { pool } = require('../db/pool');
const { authMiddleware } = require('../middleware/auth');
const { validate } = require('../middleware/validate');

const router = Router();

router.post('/', authMiddleware, validate('studySession'), async (req, res, next) => {
  const { durationMs } = req.body;
  if (durationMs < 10000) {
    // Silently ignore sessions under 10 seconds — tell client explicitly
    return res.json({ ok: true, saved: false, reason: 'Session too short' });
  }
  try {
    await pool.query(
      'INSERT INTO study_sessions (user_id, duration_ms) VALUES ($1, $2)',
      [req.userId, Math.floor(durationMs)]
    );
    res.json({ ok: true, saved: true });
  } catch (err) {
    next(err);
  }
});

router.get('/', authMiddleware, async (req, res, next) => {
  try {
    const [sessions, weekTotal] = await Promise.all([
      pool.query(`
        SELECT session_date, SUM(duration_ms) as total_ms
        FROM study_sessions WHERE user_id=$1 AND session_date >= CURRENT_DATE - INTERVAL '30 days'
        GROUP BY session_date ORDER BY session_date DESC
      `, [req.userId]),
      pool.query(`
        SELECT COALESCE(SUM(duration_ms), 0) as ms
        FROM study_sessions WHERE user_id=$1 AND session_date >= CURRENT_DATE - INTERVAL '7 days'
      `, [req.userId]),
    ]);
    res.json({
      sessions: sessions.rows,
      weekTotalMs: parseInt(weekTotal.rows[0]?.ms || 0),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
