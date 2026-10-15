'use strict';

const https = require('https');
const path = require('path');
const { exec } = require('child_process');
const router = require('express').Router();

const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// Link preview: fetch a page and return the first 2 KB.
router.get('/fetch', async (req, res, next) => {
  try {
    const response = await fetch(req.query.url);
    const body = await response.text();
    res.type('text/plain').send(body.slice(0, 2000));
  } catch (err) {
    next(err);
  }
});

router.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, stdout) => {
    res.type('text/plain').send(stdout || String(err));
  });
});

router.get('/files', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'files', req.query.name));
});

router.get('/upstream-status', (req, res) => {
  https
    .get('https://status.internal.example/health', { agent: insecureAgent }, (r) => res.json({ status: r.statusCode }))
    .on('error', () => res.status(502).json({ error: 'upstream unavailable' }));
});

module.exports = router;
