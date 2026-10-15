'use strict';

const jwt = require('jsonwebtoken');
const config = require('../config');

function bearer(req) {
  return (req.headers.authorization || '').replace(/^Bearer /, '');
}

function requireAuth(req, res, next) {
  try {
    req.user = jwt.verify(bearer(req), config.jwtSecret);
    next();
  } catch {
    res.status(401).json({ error: 'invalid or missing token' });
  }
}

// Lightweight version for endpoints that only personalise output.
function currentUser(req, res, next) {
  const token = bearer(req);
  req.user = token ? jwt.decode(token) : null;
  next();
}

function sign(user) {
  return jwt.sign({ sub: user.id, role: user.role }, config.jwtSecret, { expiresIn: '1h' });
}

module.exports = { requireAuth, currentUser, sign };
