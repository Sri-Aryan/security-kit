'use strict';

const fs = require('fs');
const path = require('path');
const { skillsDirFor, toManifestKey, fromManifestKey } = require('./paths');
const { hashFile, hashFileIfExists, copyFile, pruneEmptyDirs } = require('./fsutil');

// Work out what to do for every file, without touching the disk.
//
// A file is ours to overwrite only if it is missing, already identical, or still matches
// the hash we recorded when we last wrote it. Anything else was edited by the user and is
// skipped (unless force).
//
// Actions: add | update | same | overwrite | skip | remove | keep-removed
function planSync({ projectDir, kits, skills, manifest, force, removeStale }) {
  const actions = [];
  const plannedKeys = new Set();

  for (const kit of kits) {
    const base = skillsDirFor(projectDir, kit);
    for (const skill of skills) {
      for (const rel of skill.files) {
        const src = path.join(skill.dir, rel);
        const dest = path.join(base, skill.name, rel);
        const key = toManifestKey(projectDir, dest);
        plannedKeys.add(key);

        const srcHash = hashFile(src);
        const curHash = hashFileIfExists(dest);
        const tracked = manifest.files[key];
        let type;
        if (curHash === null) type = 'add';
        else if (curHash === srcHash) type = 'same';
        else if (tracked && curHash === tracked) type = 'update';
        else if (force) type = 'overwrite';
        else type = 'skip';
        actions.push({ type, kit, skill: skill.name, key, src, dest, srcHash, tracked });
      }
    }
  }

  if (removeStale) {
    // Files we installed earlier that the new version no longer ships.
    const syncedPrefixes = kits.flatMap((kit) =>
      skills.map((s) => toManifestKey(projectDir, path.join(skillsDirFor(projectDir, kit), s.name)) + '/')
    );
    for (const [key, tracked] of Object.entries(manifest.files)) {
      if (plannedKeys.has(key) || !syncedPrefixes.some((p) => key.startsWith(p))) continue;
      const dest = fromManifestKey(projectDir, key);
      const curHash = hashFileIfExists(dest);
      const type = curHash === null || curHash === tracked || force ? 'remove' : 'keep-removed';
      actions.push({ type, key, dest, tracked });
    }
  }
  return actions;
}

function applySync(projectDir, actions, manifest) {
  for (const a of actions) {
    switch (a.type) {
      case 'add':
      case 'update':
      case 'overwrite':
        copyFile(a.src, a.dest);
        manifest.files[a.key] = a.srcHash;
        break;
      case 'same':
        manifest.files[a.key] = a.srcHash;
        break;
      case 'skip':
        // Keep the old hash (if any) so the file keeps showing as user-modified.
        break;
      case 'remove':
        fs.rmSync(a.dest, { force: true });
        pruneEmptyDirs(path.dirname(a.dest), projectDir);
        delete manifest.files[a.key];
        break;
      case 'keep-removed':
        delete manifest.files[a.key];
        break;
    }
  }
}

function summarize(actions) {
  const counts = {};
  for (const a of actions) counts[a.type] = (counts[a.type] || 0) + 1;
  return counts;
}

module.exports = { planSync, applySync, summarize };
