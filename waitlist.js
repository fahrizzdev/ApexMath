const { Router } = require('express');
const { pool } = require('../db/pool');
const { validate } = require('../middleware/validate');

const router = Router();

router.post('/', validate('waitlist'), async (req, res, next) => {
  const { email } = req.body;
  try {
    await pool.query(
      'INSERT INTO waitlist (email) VALUES ($1) ON CONFLICT (email) DO NOTHING',
      [email]
    );
    const result = await pool.query('SELECT COUNT(*) FROM waitlist');
    res.json({ success: true, count: parseInt(result.rows[0].count) });
  } catch (err) {
    next(err);
  }
});

router.get('/count', async (req, res, next) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM waitlist');
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) {
    res.json({ count: 0 });
  }
});

module.exports = router;
