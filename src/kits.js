'use strict';

const { KITS } = require('./paths');
const { UserError } = require('./errors');

// Which agent folders to install into. Default: all of them, so every agent finds the skills without asking.
// --kit narrows it down (claude, codex, agents, or a comma-separated list).
function resolveKits(kitFlag) {
  if (!kitFlag || ['all', 'both'].includes(String(kitFlag).toLowerCase())) return [...KITS];
  const kits = String(kitFlag).toLowerCase().split(',').map((k) => k.trim()).filter(Boolean);
  const bad = kits.filter((k) => !KITS.includes(k));
  if (bad.length || !kits.length) {
    throw new UserError(`Invalid --kit "${kitFlag}"`, `Use one or more of: ${KITS.join(', ')} (default: all).`);
  }
  return [...new Set(kits)];
}

module.exports = { resolveKits };
