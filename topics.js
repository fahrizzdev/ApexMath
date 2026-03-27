const { Router } = require('express');
const { pool } = require('../db/pool');
const { authMiddleware } = require('../middleware/auth');
const { validate } = require('../middleware/validate');
const { TOPIC_LESSON_MAP } = require('../data/questions');

const router = Router();

// Track a single answer
router.post('/track', authMiddleware, validate('trackAnswer'), async (req, res, next) => {
  const { topic, correct } = req.body;
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
    next(err);
  }
});

// Get full topic performance
router.get('/performance', authMiddleware, async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT topic, correct_count, wrong_count, last_seen FROM topic_performance WHERE user_id=$1 ORDER BY wrong_count DESC',
      [req.userId]
    );
    const rows = result.rows.map(r => ({ ...r, lesson: TOPIC_LESSON_MAP[r.topic] || null }));
    res.json({ topics: rows });
  } catch (err) {
    next(err);
  }
});

// Look up lesson for a topic
router.get('/lesson/:topic', (req, res) => {
  const lesson = TOPIC_LESSON_MAP[decodeURIComponent(req.params.topic)];
  if (!lesson) return res.json({ found: false });
  res.json({ found: true, ...lesson });
});

// ── Badges (DB-backed) ─────────────────────────────────────────────────────────

router.get('/badges', authMiddleware, async (req, res, next) => {
  try {
    const result = await pool.query(
      'SELECT badge_id, earned_at FROM user_badges WHERE user_id=$1',
      [req.userId]
    );
    res.json({ badges: result.rows });
  } catch (err) {
    next(err);
  }
});

router.post('/badges/award', authMiddleware, async (req, res, next) => {
  const { badgeId } = req.body;
  if (!badgeId || typeof badgeId !== 'string') {
    return res.status(400).json({ error: 'Invalid badgeId' });
  }
  try {
    await pool.query(`
      INSERT INTO user_badges (user_id, badge_id)
      VALUES ($1, $2)
      ON CONFLICT (user_id, badge_id) DO NOTHING
    `, [req.userId, badgeId]);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
