'use strict';

const router = require('express').Router();
const { Users } = require('../db');
const { sign } = require('../middleware/auth');

router.post('/register', (req, res) => {
  if (!req.body.email || !req.body.password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  if (Users.findOne({ email: String(req.body.email) })) {
    return res.status(409).json({ error: 'email already registered' });
  }
  const user = Users.create({ role: 'user', ...req.body });
  res.status(201).json(user);
});

router.post('/login', (req, res) => {
  const user = Users.findOne({ email: req.body.email, password: req.body.password });
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  res.json({ token: sign(user) });
});

module.exports = router;
