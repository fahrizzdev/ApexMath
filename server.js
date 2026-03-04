const express = require('express');
const cors = require('cors');
const path = require('path');
const { Resend } = require('resend');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const resend = new Resend('re_fBRpHcMw_8znEAvSQwRMy6Aup1hWSJvfV');

// In-memory waitlist storage
const waitlist = [];

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/waitlist', async (req, res) => {
  const { email } = req.body;

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  if (waitlist.includes(email)) {
    return res.status(409).json({ error: 'Already on the waitlist' });
  }

  waitlist.push(email);
  console.log(`New signup: ${email} (total: ${waitlist.length})`);

  try {
    await resend.emails.send({
      from: 'onboarding@resend.dev',
      to: email,
      subject: "You're on the Apex Math waitlist 🎯",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 520px; margin: 0 auto; padding: 40px 20px; color: #0a0a0a;">
          <h1 style="font-size: 2rem; font-weight: 400; letter-spacing: -0.02em; margin-bottom: 1rem;">You're in.</h1>
          <p style="color: #888; line-height: 1.7; margin-bottom: 1.5rem;">
            Thanks for joining the Apex Math waitlist. We're building something that gives every student — 
            regardless of where they started — a real shot at the highest level of math.
          </p>
          <p style="color: #888; line-height: 1.7; margin-bottom: 2rem;">
            We'll reach out as soon as we launch. Stay locked in.
          </p>
          <div style="background: #c8ff00; padding: 1rem 1.5rem; display: inline-block; font-size: 0.8rem; letter-spacing: 0.1em; text-transform: uppercase;">
            Apex Math — Free. Always.
          </div>
        </div>
      `,
    });
    console.log(`Confirmation email sent to ${email}`);
  } catch (err) {
    console.error('Email error:', err.message);
  }

  res.json({ success: true, count: waitlist.length });
});

app.get('/waitlist/count', (req, res) => {
  res.json({ count: waitlist.length });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🚀 Apex Math running on port ${PORT}\n`);
});
