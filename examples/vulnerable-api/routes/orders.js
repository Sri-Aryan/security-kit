'use strict';

const router = require('express').Router();
const { Orders } = require('../db');

router.get('/', (req, res) => {
  res.json(Orders.find({ userId: req.user.sub }));
});

router.get('/:id', (req, res) => {
  const order = Orders.findOne({ id: Number(req.params.id) });
  if (!order) return res.status(404).json({ error: 'not found' });
  res.json(order);
});

module.exports = router;
