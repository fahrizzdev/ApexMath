const { Router } = require('express');
const { pool } = require('../db/pool');
const { questions, LEVEL_NAMES } = require('../data/questions');
const { authMiddleware } = require('../middleware/auth');
const { validate } = require('../middleware/validate');

const router = Router();

router.get('/questions', authMiddleware, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT level FROM users WHERE id=$1', [req.userId]);
    const level = result.rows[0]?.level || 0;

    const topicPerf = await pool.query(
      'SELECT topic, wrong_count FROM topic_performance WHERE user_id=$1 ORDER BY wrong_count DESC LIMIT 5',
      [req.userId]
    );
    const weakTopics = new Set(topicPerf.rows.map(r => r.topic));

    const pool_q = questions[level];
    // Weight weak-topic questions 3x, then shuffle and deduplicate
    const weighted = pool_q.flatMap(q => weakTopics.has(q.topic) ? [q, q, q] : [q]);
    const shuffled = [...weighted].sort(() => Math.random() - 0.5);
    const seen = new Set();
    const selected = [];
    for (const q of shuffled) {
      if (!seen.has(q.q)) { seen.add(q.q); selected.push(q); }
      if (selected.length >= 5) break;
    }
    // Pad if needed
    if (selected.length < 5) {
      const remaining = pool_q.filter(q => !selected.includes(q)).sort(() => Math.random() - 0.5);
      selected.push(...remaining.slice(0, 5 - selected.length));
    }

    res.json({ questions: selected.slice(0, 5), level, levelName: LEVEL_NAMES[level] });
  } catch (err) {
    next(err);
  }
});

router.post('/complete', authMiddleware, validate('dailyComplete'), async (req, res, next) => {
  const { score, topicResults } = req.body;
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

    await pool.query(
      'UPDATE users SET streak=$1, last_quiz_date=NOW() WHERE id=$2',
      [newStreak, req.userId]
    );

    await pool.query(
      `INSERT INTO daily_quiz_results (user_id, quiz_date, score, total, passed, topic_results)
       VALUES ($1, CURRENT_DATE, $2, 5, $3, $4)
       ON CONFLICT (user_id, quiz_date) DO UPDATE
       SET score=$2, passed=$3, topic_results=$4`,
      [req.userId, score, passed, JSON.stringify(topicResults || [])]
    );

    // Update topic performance
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
    next(err);
  }
});

module.exports = router;
