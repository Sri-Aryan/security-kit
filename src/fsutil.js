'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function hashFile(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function hashFileIfExists(file) {
  try {
    return hashFile(file);
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
}

// All files under dir, as paths relative to dir, sorted for stable output.
function listFiles(dir) {
  const out = [];
  const walk = (rel) => {
    for (const entry of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
      const childRel = rel ? path.join(rel, entry.name) : entry.name;
      if (entry.isDirectory()) {
        if (entry.name === '__pycache__' || entry.name === 'node_modules') continue;
        walk(childRel);
      } else if (entry.isFile()) {
        out.push(childRel);
      }
    }
  };
  walk('');
  return out.sort();
}

function copyFile(src, dest) {
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  // Keep scripts executable on macOS/Linux.
  if (process.platform !== 'win32') {
    const mode = fs.statSync(src).mode;
    if (mode & 0o111) fs.chmodSync(dest, mode & 0o777);
  }
}

// Remove empty parent directories up to (not including) stopAt.
function pruneEmptyDirs(start, stopAt) {
  let dir = start;
  while (dir.startsWith(stopAt) && dir !== stopAt) {
    try {
      if (fs.readdirSync(dir).length > 0) return;
      fs.rmdirSync(dir);
    } catch {
      return;
    }
    dir = path.dirname(dir);
  }
}

module.exports = { hashFile, hashFileIfExists, listFiles, copyFile, pruneEmptyDirs };
