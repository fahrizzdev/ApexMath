# Scalar – Pre-Launch Checklist & Migration Guide

## 1. Install new dependencies

```bash
npm install
```

New packages added: `helmet`, `express-rate-limit`, `validator`, `zod`

---

## 2. Move your HTML/JS/CSS into a `/public` folder

**This is the most critical structural change.**

The old server served `__dirname` as static files, meaning anyone could
visit `yoursite.com/server.js` and read your backend source + fallback secret.

**Steps:**
```bash
mkdir public
mv index.html public/
mv lessons.html public/
# Move any other .html, .css, .js frontend files here too
# Do NOT move server.js, questions.js, package.json — those stay in root
```

Your folder structure should look like:
```
/
├── public/
│   ├── index.html
│   ├── lessons.html
│   └── (any other frontend assets)
├── server.js        ← stays here, NOT in public/
├── questions.js     ← stays here
├── package.json     ← stays here
└── node_modules/
```

---

## 3. Set environment variables

### Required in production:
| Variable | Description | Example |
|---|---|---|
| `JWT_SECRET` | Long random string, min 32 chars | `openssl rand -hex 32` |
| `DATABASE_URL` | Postgres connection string | `postgresql://user:pass@host/db` |
| `ALLOWED_ORIGIN` | Your frontend domain | `https://scalar.app` |
| `NODE_ENV` | Must be `production` in prod | `production` |

**Generate a strong JWT secret:**
```bash
openssl rand -hex 32
```

If `NODE_ENV=production` and `JWT_SECRET` is not set, the server will **refuse to start**.
This is intentional — it prevents accidentally deploying with the dev secret.

---

## 4. Token expiry migration

Tokens now expire after **24 hours**. Old tokens (issued before this update)
used `base64` encoding; new tokens use `base64url`. Old tokens will fail
signature verification and users will be logged out once — this is expected
and safe. They simply log back in to get a fresh token.

---

## 5. Password minimum raised to 8 characters

Existing passwords are unaffected (they're hashed — you can't retroactively
enforce length on stored hashes). New registrations and password changes
now require 8+ characters. You may want to add a note in your UI prompting
existing users to update short passwords.

---

## 6. The `/result` route now requires authentication

Previously `/result` accepted unauthenticated requests and would update any
user's level by passing a `userId` in the request body. This is now locked
behind `authMiddleware`. If any frontend code calls `/result` without a
token, it will receive a 401. Update the frontend to pass the auth token
on this request (same as all other authenticated calls).

---

## 7. Weak-topic decay is now active

When a user answers a topic correctly, their `wrong_count` for that topic
decreases by 1 (minimum 0). Previously, wrong counts only ever went up,
meaning a topic would stay "weak" forever even after mastery. The dashboard
weak-spots list will now clear topics as users improve.

---

## 8. daily_quiz_results UNIQUE constraint

Added `UNIQUE(user_id, quiz_date)` to `daily_quiz_results`. If your DB
already has this table without the constraint, run:

```sql
ALTER TABLE daily_quiz_results
  ADD CONSTRAINT daily_quiz_results_user_date_unique
  UNIQUE (user_id, quiz_date);
```

If there are duplicate rows for the same user+date, deduplicate first:
```sql
DELETE FROM daily_quiz_results a
USING daily_quiz_results b
WHERE a.id < b.id AND a.user_id = b.user_id AND a.quiz_date = b.quiz_date;
```

---

## 9. CSP headers (Content Security Policy)

`helmet` now adds a CSP header. If you use any CDN URLs not listed in
`server.js` (e.g., a different KaTeX CDN), add them to the `scriptSrc`
or `styleSrc` arrays in the helmet config, or you'll see console errors
and broken renders.

Current allowed script/style origins:
- `cdn.jsdelivr.net`
- `cdnjs.cloudflare.com`
- `fonts.googleapis.com` / `fonts.gstatic.com`

---

## 10. Rate limits

| Route | Window | Max requests |
|---|---|---|
| `/auth/*` | 15 min | 20 |
| `/waitlist` | 1 min | 120 |
| `/question` | 1 min | 120 |

These are conservative starting values. Adjust in `server.js` if legitimate
users hit them.

---

## What's still on you: the question bank

The only unfixable-by-code issue: you have ~15–30 questions per level.
A motivated user exhausts a level in one session. Target: **50+ per level**.

Fastest path:
1. Use an AI to generate 50 candidates per topic in your `questions.js` format
2. Review every single one for mathematical correctness before shipping
3. Pay special attention to `ans` index (0-based), `opts` ordering, and `steps`

That review step cannot be skipped — wrong math in a math tutor is worse
than no math tutor.
