// Semgrep rule tests for skills/sk-api/rules/api.yml (JavaScript).
// "ruleid: X" = rule X must match the next line; "ok: X" = rule X must not match it.
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { exec, execFile } = require('child_process');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const app = express();
const router = express.Router();

// ---- API-AUTHN-001 / API-AUTHZ-002
// ruleid: sk-express-state-change-without-middleware
router.post('/orders', (req, res) => res.json({}));
// ok: sk-express-state-change-without-middleware
router.post('/orders', requireAuth, (req, res) => res.json({}));
// ok: sk-express-state-change-without-middleware
// ruleid: sk-login-without-rate-limit-express
router.post('/login', (req, res) => res.json({}));
// ruleid: sk-express-admin-route-without-middleware
app.get('/admin/users', (req, res) => res.json([]));
// ok: sk-express-admin-route-without-middleware
app.get('/admin/users', requireAdmin, (req, res) => res.json([]));

// ---- API-AUTHN-002 / 003
function whoami(token) {
  // ruleid: sk-jwt-decode-without-verify-js
  return jwt.decode(token);
}
// ruleid: sk-jwt-none-algorithm
jwt.verify(token, key, { algorithms: ['HS256', 'none'] });
// ruleid: sk-jwt-verify-algorithms-not-pinned
jwt.verify(token, key);
// ok: sk-jwt-verify-algorithms-not-pinned
jwt.verify(token, key, { algorithms: ['HS256'] });

// ---- API-AUTHN-004
// ruleid: sk-login-without-rate-limit-express
app.post('/api/login', async (req, res) => { res.json({}); });
// ok: sk-login-without-rate-limit-express
app.post('/api/login', loginLimiter, async (req, res) => { res.json({}); });

// ---- API-AUTHZ-001
// ruleid: sk-express-idor-param-lookup-without-user
router.get('/orders/:id', async (req, res) => {
  const order = await db.get('SELECT * FROM orders WHERE id = ?', [req.params.id]);
  res.json(order);
});
// ok: sk-express-idor-param-lookup-without-user
router.get('/orders/:id', async (req, res) => {
  const order = await db.get('SELECT * FROM orders WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  res.json(order);
});

// ---- API-AUTHZ-003
async function updateProfile(req, res) {
  // ruleid: sk-mass-assignment-js
  await User.update(req.user.id, req.body);
  // ruleid: sk-mass-assignment-js
  const u = { ...req.body, id: 1 };
  // ruleid: sk-mass-assignment-js
  Object.assign(user, req.body);
  // ok: sk-mass-assignment-js
  await User.update(req.user.id, { name: req.body.name });
}

// ---- API-INJ-001
async function search(req, res) {
  // ruleid: sk-sql-injection-js, sk-sql-string-building
  const rows = await db.all("SELECT * FROM products WHERE name LIKE '%" + req.query.q + "%'");
  // ruleid: sk-sql-injection-js, sk-sql-string-building
  await pool.query(`SELECT * FROM users WHERE email = '${req.body.email}'`);
  // ok: sk-sql-injection-js
  await pool.query('SELECT * FROM users WHERE email = $1', [req.body.email]);
}
// ruleid: sk-sql-string-building
const q = "SELECT * FROM t WHERE id = " + id;

// ---- API-INJ-002
async function login(req, res) {
  // ruleid: sk-nosql-operator-injection
  const user = await Users.findOne({ email: req.body.email, password: req.body.password });
  // ok: sk-nosql-operator-injection
  const u2 = await Users.findOne({ email: String(req.body.email) });
}

// ---- API-INJ-003
function ping(req, res) {
  // ruleid: sk-command-injection-js
  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));
  // ok: sk-command-injection-js
  execFile('ping', ['-c', '1', req.query.host]);
}

// ---- API-INJ-004
function download(req, res) {
  // ruleid: sk-path-traversal-js
  res.sendFile(path.join(__dirname, 'files', req.query.name));
  // ok: sk-path-traversal-js
  res.sendFile(path.join(__dirname, 'files', path.basename(req.query.name)));
}

// ---- API-SSRF-001
async function preview(req, res) {
  // ruleid: sk-ssrf-js
  const r = await axios.get(req.query.url);
  // ruleid: sk-ssrf-js
  const r2 = await fetch(req.body.target);
  // ok: sk-ssrf-js
  const r3 = await fetch('https://api.example.com/x');
}

// ---- API-ERR-001
function onError(err, req, res, next) {
  // ruleid: sk-stack-trace-in-response-js
  res.status(500).json({ message: err.message, stack: err.stack });
}
function onError2(err, req, res, next) {
  // ok: sk-stack-trace-in-response-js
  res.status(500).json({ message: 'Internal error' });
}

// ---- API-CFG-001
// ruleid: sk-cors-wildcard-credentials-js
app.use(cors({ origin: true, credentials: true }));
// ok: sk-cors-wildcard-credentials-js
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
function manualCors(req, res, next) {
  // ruleid: sk-cors-wildcard-credentials-js
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
}

// ---- API-CFG-002 / 003
// ruleid: sk-debug-mode-other
app.use(errorhandler());
// ruleid: sk-tls-verify-disabled
const agent = new https.Agent({ rejectUnauthorized: false });

// ---- API-SECRET-001
// ruleid: sk-hardcoded-secret-js
const JWT_SECRET = 'supersecret-signing-key-123';
// ruleid: sk-hardcoded-secret-js
const key = process.env.API_KEY || 'live-key-9f8e7d6c5b4a';
// ok: sk-hardcoded-secret-js
const SECRET = process.env.JWT_SECRET;
// ok: sk-hardcoded-secret-js
const password = 'changeme';
// ruleid: sk-hardcoded-jwt-key
jwt.sign({ sub: 1 }, 'inline-secret-value');
// ruleid: sk-known-secret-formats
const aws = 'AKIAIOSFODNN7EXAMPLE';
