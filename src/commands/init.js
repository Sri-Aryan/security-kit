'use strict';

const log = require('../log');
const { c } = log;
const { KIT_TARGETS, resolveInstallRoot, skillsDirFor, manifestPath, displayPath } = require('../paths');
const { resolveKits } = require('../kits');
const { selectSkills } = require('../skills');
const { readManifest, writeManifest, emptyManifest } = require('../manifest');
const { planSync, applySync } = require('../sync');
const { printSyncResult } = require('../report');
const { KIT_VERSION } = require('../version');
const { UserError } = require('../errors');

// Installs the skills without asking anything: for every agent, in the home folder (all projects) by default,
// or in one project with --project / --dir.
async function init(flags) {
  const root = resolveInstallRoot(flags);
  const kits = resolveKits(flags.kit);
  const skills = selectSkills(flags.skills);
  if (!skills.length) throw new UserError('No skills found in this package. The download may be incomplete.');

  const manifest = readManifest(root.dir) || emptyManifest(KIT_VERSION);
  const actions = planSync({ projectDir: root.dir, kits, skills, manifest, force: flags.force, removeStale: false });

  const where = root.scope === 'global' ? 'all projects (your home folder)' : root.dir;
  log.heading(`SecurityKit ${KIT_VERSION} → ${where}`);
  log.info(`  Skills: ${flags.skills ? skills.map((s) => s.name).join(', ') : `all ${skills.length} (see them with: securitykit skills)`}`);

  if (flags['dry-run']) {
    printSyncResult(actions, { dryRun: true });
    return 0;
  }

  applySync(root.dir, actions, manifest);
  const now = new Date().toISOString();
  manifest.kitVersion = KIT_VERSION;
  manifest.scope = root.scope;
  manifest.installedAt = manifest.installedAt || now;
  manifest.updatedAt = now;
  manifest.kits = [...new Set([...manifest.kits, ...kits])].sort();
  for (const s of skills) manifest.skills[s.name] = { version: s.version || KIT_VERSION };
  writeManifest(root.dir, manifest);

  printSyncResult(actions);
  for (const kit of kits) {
    log.ok(`${KIT_TARGETS[kit].label.padEnd(38)} ${displayPath(root, skillsDirFor(root.dir, kit))}`);
  }
  log.dim(`  Manifest: ${displayPath(root, manifestPath(root.dir))}`);
  log.heading('Next');
  if (root.scope === 'global') {
    log.info(`  Open any project in your AI agent and run ${c.cyan('/sk-help')} to see what to run first,`);
  } else {
    log.info(`  Open this project in your AI agent and run ${c.cyan('/sk-help')} to see what to run first,`);
  }
  log.info(`  or start with ${c.cyan('/sk-audit')} (whole project) or ${c.cyan('/sk-review')} (your current changes).`);
  log.dim('  Agent not listed? Point it at the .agents/skills folder, or see the README.');
  return 0;
}

module.exports = init;
