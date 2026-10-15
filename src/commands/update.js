'use strict';

const log = require('../log');
const { resolveProjectDir } = require('../paths');
const { availableSkills } = require('../skills');
const { readManifest, writeManifest } = require('../manifest');
const { planSync, applySync } = require('../sync');
const { printSyncResult } = require('../report');
const { KIT_VERSION } = require('../version');
const { UserError } = require('../errors');

async function update(flags) {
  if (flags.kit || flags.skills) {
    throw new UserError(
      'update re-syncs what is already installed and does not take --kit or --skills.',
      'To add agents or skills, run "securitykit init --kit ... --skills ..." instead.'
    );
  }
  const projectDir = resolveProjectDir(flags.dir);
  const manifest = readManifest(projectDir);
  if (!manifest) {
    throw new UserError(
      'SecurityKit is not installed in this project (no .securitykit/manifest.json).',
      'Run: npx github:getsecuritykit/kit init'
    );
  }

  const shipped = new Map(availableSkills().map((s) => [s.name, s]));
  const installedNames = Object.keys(manifest.skills);
  const skills = installedNames.filter((n) => shipped.has(n)).map((n) => shipped.get(n));
  const dropped = installedNames.filter((n) => !shipped.has(n));
  const notInstalled = [...shipped.keys()].filter((n) => !manifest.skills[n]);

  const actions = planSync({
    projectDir,
    kits: manifest.kits,
    skills,
    manifest,
    force: flags.force,
    removeStale: true,
  });

  log.heading(`SecurityKit update ${manifest.kitVersion || '?'} → ${KIT_VERSION}`);
  if (flags['dry-run']) {
    printSyncResult(actions, { dryRun: true });
    return 0;
  }

  applySync(projectDir, actions, manifest);
  manifest.kitVersion = KIT_VERSION;
  manifest.updatedAt = new Date().toISOString();
  for (const s of skills) manifest.skills[s.name] = { version: s.version || KIT_VERSION };
  writeManifest(projectDir, manifest);

  printSyncResult(actions);
  if (dropped.length) {
    log.warn(`No longer shipped (left as-is): ${dropped.join(', ')}`);
  }
  if (notInstalled.length) {
    log.info(`New skills available: ${notInstalled.join(', ')}  (install with: securitykit init --skills ${notInstalled.join(',')})`);
  }
  log.ok('Update complete.');
  return 0;
}

module.exports = update;
