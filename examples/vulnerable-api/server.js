'use strict';

// Deliberately vulnerable API used to test SecurityKit. DO NOT DEPLOY.

const express = require('express');
const cors = require('cors');
const config = require('./config');
const { requireAuth, currentUser } = require('./middleware/auth');
const { Users, Orders } = require('./db');
const authRoutes = require('./routes/auth');
const orderRoutes = require('./routes/orders');
const productRoutes = require('./routes/products');
const toolRoutes = require('./routes/tools');

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

app.get('/health', (req, res) => res.json({ ok: true }));

app.use('/api/auth', authRoutes);
app.use('/api/orders', requireAuth, orderRoutes);
app.use('/api/products', productRoutes);
app.use('/api/tools', requireAuth, toolRoutes);

app.get('/api/profile', currentUser, (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'login required' });
  const user = Users.findOne({ id: req.user.sub });
  if (!user) return res.status(404).json({ error: 'not found' });
  res.json({ id: user.id, email: user.email, name: user.name, role: user.role });
});

app.get('/api/admin/stats', (req, res) => {
  res.json({ users: Users.count(), orders: Orders.count(), revenue: Orders.sum('total') });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  res.status(500).json({ error: err.message, stack: err.stack });
});

if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`vulnerable-api listening on http://localhost:${config.port}`);
  });
}

module.exports = app;
