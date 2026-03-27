const { Router } = require('express');
const { pool } = require('../db/pool');
const { questions, LEVEL_NAMES } = require('../data/questions');
const { validate } = require('../middleware/validate');

const router = Router();

router.post('/', validate('question'), async (req, res, next) => {
  const { sessionId, currentLevel, correct, wrong, userId } = req.body;

  try {
    let session;
    const existing = await pool.query(
      'SELECT * FROM question_sessions WHERE session_id = $1',
      [sessionId]
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
        'UPDATE question_sessions SET seen_keys = seen_keys || $1::text[], current_level = $2, updated_at = NOW() WHERE session_id = $3',
        [[newKey], tryLevel, sessionId]
      );
      return res.json({ question: fallback[idx], level: tryLevel, levelName: LEVEL_NAMES[tryLevel], done: false });
    }

    const idx = Math.floor(Math.random() * unseen.length);
    const origIdx = pool_q.indexOf(unseen[idx]);
    const newKey = `${level}-${origIdx}`;
    await pool.query(
      'UPDATE question_sessions SET seen_keys = seen_keys || $1::text[], current_level = $2, updated_at = NOW() WHERE session_id = $3',
      [[newKey], level, sessionId]
    );

    res.json({ question: unseen[idx], level, levelName: LEVEL_NAMES[level], done: false });
  } catch (err) {
    // Graceful fallback to random question if DB fails
    console.error('Question DB error, falling back:', err.message);
    const level = currentLevel || 1;
    const pool_q = questions[level];
    const q = pool_q[Math.floor(Math.random() * pool_q.length)];
    res.json({ question: q, level, levelName: LEVEL_NAMES[level], done: false });
  }
});

module.exports = router;
