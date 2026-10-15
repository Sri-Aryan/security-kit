'use strict';

const router = require('express').Router();
const { db } = require('../db');

router.get('/', (req, res) => {
  res.json(db.all('SELECT id, name, price FROM products ORDER BY id'));
});

router.get('/search', (req, res) => {
  const rows = db.all("SELECT id, name, price FROM products WHERE name LIKE '%" + req.query.q + "%'");
  res.json(rows);
});

router.post('/', (req, res) => {
  const { name, price } = req.body;
  db.run('INSERT INTO products (name, price, cost) VALUES (?, ?, 0)', [String(name), Number(price)]);
  res.status(201).json({ ok: true });
});

module.exports = router;
