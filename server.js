require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

const app = express();
const db = new Database('./db/app.db');

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', './views');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const PORT = process.env.PORT || 3000;

// Initialize database
const initDb = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      stripe_customer_id TEXT,
      subscription_status TEXT DEFAULT 'inactive',
      plan TEXT DEFAULT 'free',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS forms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      fields TEXT NOT NULL,
      webhook_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
    
    CREATE TABLE IF NOT EXISTS submissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      form_id INTEGER NOT NULL,
      data TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (form_id) REFERENCES forms(id)
    );
  `);
};
initDb();

// Auth middleware
const auth = (req, res, next) => {
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.redirect('/login');
  
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.redirect('/login');
  }
};

const apiAuth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Helper: Check form limit
const checkFormLimit = (userId) => {
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(userId);
  if (user.plan === 'pro') return { allowed: true };
  
  const count = db.prepare('SELECT COUNT(*) as count FROM forms WHERE user_id = ?').get(userId).count;
  return { allowed: count < 1, count };
};

// Helper: Check submission limit
const checkSubmissionLimit = (formId) => {
  const form = db.prepare('SELECT user_id FROM forms WHERE id = ?').get(formId);
  const user = db.prepare('SELECT plan FROM users WHERE id = ?').get(form.user_id);
  if (user.plan === 'pro') return { allowed: true };
  
  const startOfMonth = new Date();
  startOfMonth.setDate(1);
  startOfMonth.setHours(0, 0, 0, 0);
  
  const count = db.prepare(`
    SELECT COUNT(*) as count FROM submissions 
    WHERE form_id = ? AND created_at >= ?
  `).get(formId, startOfMonth.toISOString()).count;
  
  return { allowed: count < 10, count };
};

// Routes

// Landing page
app.get('/', (req, res) => {
  res.render('landing');
});

// Auth pages
app.get('/signup', (req, res) => res.render('signup'));
app.get('/login', (req, res) => res.render('login'));

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  
  try {
    const result = db.prepare('INSERT INTO users (email, password) VALUES (?, ?)').run(email, hashedPassword);
    const token = jwt.sign({ id: result.lastInsertRowid, email }, JWT_SECRET);
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/dashboard');
  } catch (e) {
    res.render('signup', { error: 'Email already exists' });
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.render('login', { error: 'Invalid credentials' });
  }
  
  const token = jwt.sign({ id: user.id, email: user.email, plan: user.plan }, JWT_SECRET);
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

// Dashboard
app.get('/dashboard', auth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const forms = db.prepare('SELECT * FROM forms WHERE user_id = ?').all(req.user.id);
  
  // Get submission counts for each form
  const formsWithCounts = forms.map(form => {
    const count = db.prepare('SELECT COUNT(*) as count FROM submissions WHERE form_id = ?').get(form.id).count;
    return { ...form, submissionCount: count };
  });
  
  res.render('dashboard', { user, forms: formsWithCounts });
});

// Form builder
app.get('/forms/new', auth, (req, res) => {
  const limit = checkFormLimit(req.user.id);
  if (!limit.allowed) {
    return res.render('upgrade', { message: 'Free plan allows only 1 form. Upgrade to Pro for unlimited forms.' });
  }
  res.render('form-builder');
});

app.post('/forms', auth, (req, res) => {
  const limit = checkFormLimit(req.user.id);
  if (!limit.allowed) {
    return res.status(403).json({ error: 'Form limit reached. Upgrade to Pro.' });
  }
  
  const { name, fields, webhookUrl } = req.body;
  const slug = crypto.randomBytes(8).toString('hex');
  
  db.prepare('INSERT INTO forms (user_id, name, slug, fields, webhook_url) VALUES (?, ?, ?, ?, ?)')
    .run(req.user.id, name, slug, JSON.stringify(fields), webhookUrl || null);
  
  res.redirect('/dashboard');
});

// View form submissions
app.get('/forms/:id', auth, (req, res) => {
  const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!form) return res.status(404).send('Form not found');
  
  const submissions = db.prepare('SELECT * FROM submissions WHERE form_id = ? ORDER BY created_at DESC').all(form.id);
  res.render('form-detail', { form, submissions: submissions.map(s => ({ ...s, data: JSON.parse(s.data) })) });
});

// Public sponsor form
app.get('/sponsor/:slug', (req, res) => {
  const form = db.prepare('SELECT * FROM forms WHERE slug = ?').get(req.params.slug);
  if (!form) return res.status(404).send('Form not found');
  
  res.render('sponsor-form', { form, fields: JSON.parse(form.fields) });
});

app.post('/sponsor/:slug', async (req, res) => {
  const form = db.prepare('SELECT * FROM forms WHERE slug = ?').get(req.params.slug);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  
  const limit = checkSubmissionLimit(form.id);
  if (!limit.allowed) {
    return res.status(403).render('error', { message: 'This form has reached its monthly submission limit.' });
  }
  
  // Save submission
  db.prepare('INSERT INTO submissions (form_id, data) VALUES (?, ?)')
    .run(form.id, JSON.stringify(req.body));
  
  // Send webhook if configured
  if (form.webhook_url) {
    fetch(form.webhook_url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ form_id: form.id, data: req.body, timestamp: new Date().toISOString() })
    }).catch(() => {});
  }
  
  res.render('sponsor-success');
});

// API Endpoints
app.get('/api/submissions', apiAuth, (req, res) => {
  const { form_id } = req.query;
  
  // Verify ownership
  const form = db.prepare('SELECT * FROM forms WHERE id = ? AND user_id = ?').get(form_id, req.user.id);
  if (!form) return res.status(403).json({ error: 'Access denied' });
  
  const submissions = db.prepare('SELECT id, data, created_at FROM submissions WHERE form_id = ? ORDER BY created_at DESC')
    .all(form_id);
  
  res.json({
    form: { id: form.id, name: form.name, slug: form.slug },
    submissions: submissions.map(s => ({ id: s.id, data: JSON.parse(s.data), created_at: s.created_at }))
  });
});

app.get('/api/forms', apiAuth, (req, res) => {
  const forms = db.prepare('SELECT id, name, slug, created_at FROM forms WHERE user_id = ?').all(req.user.id);
  res.json({ forms });
});

// Stripe checkout
app.post('/create-checkout-session', auth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  
  const session = await stripe.checkout.sessions.create({
    customer_email: user.email,
    line_items: [{
      price_data: {
        currency: 'usd',
        product_data: { name: 'Pro Plan - Unlimited Forms & Submissions' },
        unit_amount: 900,
        recurring: { interval: 'month' }
      },
      quantity: 1
    }],
    mode: 'subscription',
    success_url: `${req.protocol}://${req.get('host')}/dashboard?success=true`,
    cancel_url: `${req.protocol}://${req.get('host')}/dashboard?canceled=true`
  });
  
  res.json({ url: session.url });
});

// Webhook for Stripe
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;
  
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    db.prepare('UPDATE users SET plan = ?, subscription_status = ? WHERE email = ?')
      .run('pro', 'active', session.customer_email);
  }
  
  res.json({ received: true });
});

// API docs
app.get('/api-docs', (req, res) => {
  res.render('api-docs');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});