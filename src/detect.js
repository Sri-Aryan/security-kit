'use strict';

const fs = require('fs');
const path = require('path');
const { KIT_TARGETS, KITS } = require('./paths');
const { UserError } = require('./errors');
const { canPrompt, choose } = require('./prompt');

function detectKits(projectDir) {
  return KITS.filter((kit) => fs.existsSync(path.join(projectDir, KIT_TARGETS[kit].root)));
}

function parseKitFlag(value) {
  const v = value.toLowerCase();
  if (v === 'both' || v === 'all') return [...KITS];
  if (KITS.includes(v)) return [v];
  throw new UserError(`Invalid --kit "${value}"`, 'Use --kit claude, --kit codex or --kit both.');
}

// Decide which agents to install for: explicit flag > existing folders > ask > error.
async function resolveKits(projectDir, kitFlag, { yes } = {}) {
  if (kitFlag) return { kits: parseKitFlag(kitFlag), how: 'flag' };
  const found = detectKits(projectDir);
  if (found.length) return { kits: found, how: 'detected' };
  if (yes) return { kits: [...KITS], how: 'default' };
  if (!canPrompt()) {
    throw new UserError(
      'No .claude/ or .codex/ folder found, so the target agent is unknown.',
      'Pass --kit claude, --kit codex or --kit both.'
    );
  }
  const answer = await choose('Install skills for which agent?', ['claude', 'codex', 'both'], 'both');
  return { kits: parseKitFlag(answer), how: 'asked' };
}

module.exports = { detectKits, parseKitFlag, resolveKits };
