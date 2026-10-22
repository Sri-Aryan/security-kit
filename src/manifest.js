'use strict';

const fs = require('fs');
const path = require('path');
const { manifestPath } = require('./paths');
const { UserError } = require('./errors');

const SCHEMA_VERSION = 1;

// Same file the skills' scripts write (shared/scripts/sk_outputs.py STATE_GITIGNORE; a test keeps them in step).
// Reports in .securitykit/ describe unfixed weaknesses; the manifest and suppressions are meant to be committed.
const STATE_GITIGNORE = [
  '# Written by SecurityKit. Scan results and reports describe weaknesses that may not be fixed yet, so they stay',
  "# out of git. Suppressions (ignore.json) and a project install's manifest.json are meant to be committed.",
  '*',
  '!ignore.json',
  '!manifest.json',
  '',
].join('\n');

function emptyManifest(kitVersion) {
  return {
    schemaVersion: SCHEMA_VERSION,
    kitVersion,
    installedAt: null,
    updatedAt: null,
    kits: [],
    skills: {},
    files: {},
  };
}

function readManifest(projectDir) {
  const file = manifestPath(projectDir);
  let text;
  try {
    text = fs.readFileSync(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new UserError(
      `Manifest is not valid JSON: ${file}`,
      'Fix or delete it, then run "securitykit init --force" to rebuild it.'
    );
  }
  if (data.schemaVersion > SCHEMA_VERSION) {
    throw new UserError(
      `Manifest was written by a newer SecurityKit (schema ${data.schemaVersion}).`,
      'Run the latest version: npx github:getsecuritykit/kit <command>'
    );
  }
  return { ...emptyManifest(data.kitVersion), ...data };
}

function writeManifest(projectDir, manifest) {
  const file = manifestPath(projectDir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const sorted = { ...manifest, files: Object.fromEntries(Object.entries(manifest.files).sort()) };
  fs.writeFileSync(file, JSON.stringify(sorted, null, 2) + '\n');
  const gitignore = path.join(path.dirname(file), '.gitignore');
  if (!fs.existsSync(gitignore)) fs.writeFileSync(gitignore, STATE_GITIGNORE);
}

module.exports = { SCHEMA_VERSION, STATE_GITIGNORE, emptyManifest, readManifest, writeManifest };
