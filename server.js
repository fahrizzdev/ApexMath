const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create table if it doesn't exist
pool.query(`
  CREATE TABLE IF NOT EXISTS waitlist (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
  )
`).then(() => console.log('Database ready'))
  .catch(err => console.error('DB setup error:', err.message));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/waitlist', async (req, res) => {
  const { email } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  try {
    await pool.query('INSERT INTO waitlist (email) VALUES ($1)', [email]);
    const result = await pool.query('SELECT COUNT(*) FROM waitlist');
    const count = parseInt(result.rows[0].count);
    console.log(`New signup: ${email} (total: ${count})`);
    res.json({ success: true, count });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Already on the waitlist' });
    }
    console.error('DB error:', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/waitlist/count', async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM waitlist');
    res.json({ count: parseInt(result.rows[0].count) });
  } catch (err) {
    res.json({ count: 0 });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Apex Math running on port ${PORT}\n`);
});
