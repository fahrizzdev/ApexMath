const { Router } = require('express');
const { pool } = require('../db/pool');
const { authMiddleware } = require('../middleware/auth');
const { validate } = require('../middleware/validate');

const router = Router();

router.get('/:level', authMiddleware, async (req, res, next) => {
  const level = parseInt(req.params.level);
  if (isNaN(level) || level < 0 || level > 6) {
    return res.status(400).json({ error: 'Invalid level' });
  }
  try {
    const result = await pool.query(
      'SELECT content, updated_at FROM user_notes WHERE user_id=$1 AND level=$2',
      [req.userId, level]
    );
    res.json({ content: result.rows[0]?.content || '', updatedAt: result.rows[0]?.updated_at || null });
  } catch (err) {
    next(err);
  }
});

router.post('/:level', authMiddleware, validate('notes'), async (req, res, next) => {
  const level = parseInt(req.params.level);
  if (isNaN(level) || level < 0 || level > 6) {
    return res.status(400).json({ error: 'Invalid level' });
  }
  const { content } = req.body;
  try {
    await pool.query(`
      INSERT INTO user_notes (user_id, level, content, updated_at)
      VALUES ($1, $2, $3, NOW())
      ON CONFLICT (user_id, level) DO UPDATE SET content=$3, updated_at=NOW()
    `, [req.userId, level, content]);
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
