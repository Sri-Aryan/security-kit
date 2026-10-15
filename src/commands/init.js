'use strict';

const path = require('path');
const log = require('../log');
const { c } = log;
const { KIT_TARGETS, resolveProjectDir, skillsDirFor, manifestPath } = require('../paths');
const { resolveKits } = require('../detect');
const { selectSkills } = require('../skills');
const { readManifest, writeManifest, emptyManifest } = require('../manifest');
const { planSync, applySync } = require('../sync');
const { printSyncResult } = require('../report');
const { KIT_VERSION } = require('../version');
const { UserError } = require('../errors');

async function init(flags) {
  const projectDir = resolveProjectDir(flags.dir);
  const { kits, how } = await resolveKits(projectDir, flags.kit, { yes: flags.yes });
  const skills = selectSkills(flags.skills);
  if (!skills.length) throw new UserError('No skills found in this package. The download may be incomplete.');

  const manifest = readManifest(projectDir) || emptyManifest(KIT_VERSION);
  const actions = planSync({ projectDir, kits, skills, manifest, force: flags.force, removeStale: false });

  log.heading(`SecurityKit ${KIT_VERSION} → ${projectDir}`);
  const howText = { flag: '', detected: ' (detected)', asked: '', default: ' (default)' }[how];
  log.info(`  Agents: ${kits.map((k) => KIT_TARGETS[k].label).join(', ')}${c.gray(howText)}`);
  log.info(`  Skills: ${skills.map((s) => s.name).join(', ')}`);

  if (flags['dry-run']) {
    printSyncResult(actions, { dryRun: true });
    return 0;
  }

  applySync(projectDir, actions, manifest);
  const now = new Date().toISOString();
  manifest.kitVersion = KIT_VERSION;
  manifest.installedAt = manifest.installedAt || now;
  manifest.updatedAt = now;
  manifest.kits = [...new Set([...manifest.kits, ...kits])].sort();
  for (const s of skills) manifest.skills[s.name] = { version: s.version || KIT_VERSION };
  writeManifest(projectDir, manifest);

  printSyncResult(actions);
  for (const kit of kits) {
    log.ok(`Installed into ${path.relative(projectDir, skillsDirFor(projectDir, kit)) || '.'}`);
  }
  log.dim(`  Manifest: ${path.relative(projectDir, manifestPath(projectDir))}`);
  log.heading('Next');
  log.info(`  Open your agent in this project and run ${c.cyan('/sk-api')} (or ${c.cyan('/sk-help')} to see all commands).`);
  return 0;
}

module.exports = init;
