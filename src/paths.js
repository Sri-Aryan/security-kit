'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { UserError } = require('./errors');

const PKG_ROOT = path.resolve(__dirname, '..');
const SKILLS_SRC = path.join(PKG_ROOT, 'skills');

// Where agents look for skills, relative to the install root (your home folder, or a project with --project).
// Kept in one place so a path change, or a new agent, is a one-line edit. Every install writes all of them.
const KIT_TARGETS = {
  claude: { label: 'Claude Code', root: '.claude', skillsDir: ['.claude', 'skills'] },
  codex: { label: 'OpenAI Codex', root: '.codex', skillsDir: ['.codex', 'skills'] },
  agents: { label: 'Other agents (shared .agents folder)', root: '.agents', skillsDir: ['.agents', 'skills'] },
};
const KITS = Object.keys(KIT_TARGETS);

const STATE_DIR = '.securitykit';
const MANIFEST_FILE = 'manifest.json';

// Install root: the user's home folder (global, the default) or a project (--project / --dir).
// SECURITYKIT_HOME overrides the home folder (used by tests; also handy for a shared machine profile).
function resolveInstallRoot(flags = {}) {
  if (flags.project || flags.dir) return { dir: resolveProjectDir(flags.dir), scope: 'project' };
  return { dir: resolveProjectDir(process.env.SECURITYKIT_HOME || os.homedir()), scope: 'global' };
}

// Short display form of a path under the install root: "~/.claude/skills" or ".claude/skills".
function displayPath(root, absPath) {
  const rel = path.relative(root.dir, absPath) || '.';
  return root.scope === 'global' ? `~/${rel.split(path.sep).join('/')}` : rel;
}

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
  resolveInstallRoot,
  displayPath,
  skillsDirFor,
  manifestPath,
  toManifestKey,
  fromManifestKey,
};
