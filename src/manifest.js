'use strict';

const fs = require('fs');
const path = require('path');
const { manifestPath } = require('./paths');
const { UserError } = require('./errors');

const SCHEMA_VERSION = 1;

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
}

module.exports = { SCHEMA_VERSION, emptyManifest, readManifest, writeManifest };
