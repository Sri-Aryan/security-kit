'use strict';

const log = require('../log');
const { c } = log;
const { KIT_TARGETS, resolveInstallRoot, fromManifestKey } = require('../paths');
const { availableSkills } = require('../skills');
const { readManifest } = require('../manifest');
const { hashFileIfExists } = require('../fsutil');
const { KIT_VERSION } = require('../version');

// Per-skill file status from the manifest: how many files are missing or edited.
function skillStatus(projectDir, manifest, kit, skillName) {
  const prefix = `${KIT_TARGETS[kit].skillsDir.join('/')}/${skillName}/`;
  let total = 0, missing = 0, modified = 0;
  for (const [key, hash] of Object.entries(manifest.files)) {
    if (!key.startsWith(prefix)) continue;
    total++;
    const cur = hashFileIfExists(fromManifestKey(projectDir, key));
    if (cur === null) missing++;
    else if (cur !== hash) modified++;
  }
  return { total, missing, modified };
}

async function list(flags) {
  const root = resolveInstallRoot(flags);
  const projectDir = root.dir;
  const manifest = readManifest(projectDir);
  const shipped = availableSkills();

  if (flags.json) {
    const out = { kitVersion: KIT_VERSION, installed: null, available: shipped.map(({ name, version, description }) => ({ name, version, description })) };
    if (manifest) {
      out.installed = {
        kitVersion: manifest.kitVersion,
        kits: manifest.kits,
        skills: Object.entries(manifest.skills).map(([name, info]) => ({
          name,
          version: info.version,
          status: Object.fromEntries(manifest.kits.map((k) => [k, skillStatus(projectDir, manifest, k, name)])),
        })),
      };
    }
    console.log(JSON.stringify(out, null, 2));
    return 0;
  }

  if (!manifest) {
    log.warn(root.scope === 'global' ? 'SecurityKit is not installed for your user yet' : `SecurityKit is not installed in ${projectDir}`);
    log.info(`  ${shipped.length} skills available. See them grouped with: npx github:getsecuritykit/kit skills`);
    log.info(`  Install with: npx github:getsecuritykit/kit init${root.scope === 'project' ? ' --project' : ''}`);
    return 0;
  }

  const where = root.scope === 'global' ? 'for all projects' : `in ${projectDir}`;
  log.heading(`Installed SecurityKit ${manifest.kitVersion} ${where} (updated ${manifest.updatedAt || 'unknown'})`);
  log.info(`  Agents: ${manifest.kits.map((k) => KIT_TARGETS[k].label).join(', ')}`);
  for (const [name, info] of Object.entries(manifest.skills).sort()) {
    const notes = [];
    for (const kit of manifest.kits) {
      const st = skillStatus(projectDir, manifest, kit, name);
      if (st.missing) notes.push(c.red(`${kit}: ${st.missing} missing`));
      if (st.modified) notes.push(c.yellow(`${kit}: ${st.modified} edited`));
    }
    const latest = shipped.find((s) => s.name === name);
    if (latest && latest.version && latest.version !== info.version) notes.push(c.cyan(`update available: ${latest.version}`));
    log.info(`  ${c.bold(name.padEnd(14))} ${String(info.version).padEnd(8)} ${notes.join('  ')}`);
  }
  const notInstalled = shipped.filter((s) => !manifest.skills[s.name]);
  if (notInstalled.length) {
    log.dim(`\n  Not installed: ${notInstalled.map((s) => s.name).join(', ')}`);
  }
  log.dim('  Descriptions, grouped: npx github:getsecuritykit/kit skills');
  return 0;
}

module.exports = list;
