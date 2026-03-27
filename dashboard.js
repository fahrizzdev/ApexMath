const { Router } = require('express');
const { pool } = require('../db/pool');
const { authMiddleware } = require('../middleware/auth');
const { LEVEL_NAMES, TOPIC_LESSON_MAP } = require('../data/questions');

const router = Router();

router.get('/', authMiddleware, async (req, res, next) => {
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
      `, [req.userId]),
    ]);

    if (!userRes.rows[0]) return res.status(404).json({ error: 'User not found' });
    const u = userRes.rows[0];

    const today = new Date().toISOString().split('T')[0];
    const todayResult = weekRes.rows.find(r => r.quiz_date.toISOString().split('T')[0] === today);
    const completedToday = !!todayResult;
    const passedToday = todayResult?.passed || false;

    const totalQuizzes = await pool.query(
      'SELECT COUNT(*) FROM daily_quiz_results WHERE user_id=$1',
      [req.userId]
    );

    const weakTopics = topicRes.rows
      .filter(t => t.wrong_count > 0)
      .sort((a, b) => b.wrong_count - a.wrong_count)
      .slice(0, 10)
      .map(t => ({
        topic: t.topic,
        wrong: t.wrong_count,
        correct: t.correct_count,
        lesson: TOPIC_LESSON_MAP[t.topic] || null,
      }));

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
    next(err);
  }
});

module.exports = router;
