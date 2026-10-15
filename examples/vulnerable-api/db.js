'use strict';

// In-memory data. Users/orders use a tiny Mongo-style query matcher; products use SQLite
// (node:sqlite, Node 22.5+) so SQL behaves like a real database.

const users = [
  { id: 1, email: 'admin@example.test', password: 'admin-pass', role: 'admin', name: 'Admin' },
  { id: 2, email: 'alice@example.test', password: 'alice-pass', role: 'user', name: 'Alice' },
  { id: 3, email: 'bob@example.test', password: 'bob-pass', role: 'user', name: 'Bob' },
];

const orders = [
  { id: 101, userId: 2, total: 42.5, items: ['keyboard'], shippingAddress: '1 Alice Street' },
  { id: 102, userId: 3, total: 18.0, items: ['mouse'], shippingAddress: '7 Bob Road' },
  { id: 103, userId: 2, total: 99.9, items: ['monitor'], shippingAddress: '1 Alice Street' },
];

function matches(doc, query) {
  return Object.entries(query).every(([key, cond]) => {
    const value = doc[key];
    if (cond && typeof cond === 'object') {
      if ('$ne' in cond && value === cond.$ne) return false;
      if ('$gt' in cond && !(value > cond.$gt)) return false;
      if ('$regex' in cond && !new RegExp(cond.$regex).test(String(value))) return false;
      return true;
    }
    return value === cond;
  });
}

function collection(docs) {
  return {
    find: (query = {}) => docs.filter((d) => matches(d, query)),
    findOne: (query = {}) => docs.find((d) => matches(d, query)) || null,
    create(doc) {
      const created = { id: Math.max(0, ...docs.map((d) => d.id)) + 1, ...doc };
      docs.push(created);
      return created;
    },
    count: () => docs.length,
    sum: (field) => docs.reduce((acc, d) => acc + (Number(d[field]) || 0), 0),
  };
}

let sqlite = null;
try {
  const { DatabaseSync } = require('node:sqlite');
  sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`
    CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL, cost REAL);
    INSERT INTO products (name, price, cost) VALUES
      ('keyboard', 49.0, 12.0), ('mouse', 19.0, 4.0), ('monitor', 199.0, 120.0);
  `);
} catch {
  // Older Node: product routes return 500. Static scanning does not need a working database.
}

const db = {
  all(sql, params = []) {
    if (!sqlite) throw new Error('node:sqlite is unavailable (Node 22.5+ required)');
    return sqlite.prepare(sql).all(...params);
  },
  run(sql, params = []) {
    if (!sqlite) throw new Error('node:sqlite is unavailable (Node 22.5+ required)');
    return sqlite.prepare(sql).run(...params);
  },
};

module.exports = { Users: collection(users), Orders: collection(orders), db };
