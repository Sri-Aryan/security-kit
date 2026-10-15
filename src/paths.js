'use strict';

const fs = require('fs');
const path = require('path');
const { UserError } = require('./errors');

const PKG_ROOT = path.resolve(__dirname, '..');
const SKILLS_SRC = path.join(PKG_ROOT, 'skills');

// Where each agent looks for project-level skills. Kept in one place so a path change is a one-line fix.
const KIT_TARGETS = {
  claude: { label: 'Claude Code', root: '.claude', skillsDir: ['.claude', 'skills'] },
  codex: { label: 'OpenAI Codex', root: '.codex', skillsDir: ['.codex', 'skills'] },
};
const KITS = Object.keys(KIT_TARGETS);

const STATE_DIR = '.securitykit';
const MANIFEST_FILE = 'manifest.json';

function resolveProjectDir(dirFlag) {
  const dir = path.resolve(dirFlag || process.cwd());
  let stat;
  try {
    stat = fs.statSync(dir);
  } catch {
    throw new UserError(`Project directory does not exist: ${dir}`);
  }
  if (!stat.isDirectory()) throw new UserError(`Not a directory: ${dir}`);
  return dir;
}

function skillsDirFor(projectDir, kit) {
  return path.join(projectDir, ...KIT_TARGETS[kit].skillsDir);
}

function manifestPath(projectDir) {
  return path.join(projectDir, STATE_DIR, MANIFEST_FILE);
}

// Manifest keys are always forward-slash paths relative to the project, so a manifest
// written on Windows still works on macOS/Linux (and vice versa).
function toManifestKey(projectDir, absPath) {
  return path.relative(projectDir, absPath).split(path.sep).join('/');
}

function fromManifestKey(projectDir, key) {
  return path.join(projectDir, ...key.split('/'));
}

module.exports = {
  PKG_ROOT,
  SKILLS_SRC,
  KIT_TARGETS,
  KITS,
  STATE_DIR,
  resolveProjectDir,
  skillsDirFor,
  manifestPath,
  toManifestKey,
  fromManifestKey,
};
