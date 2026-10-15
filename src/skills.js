'use strict';

const fs = require('fs');
const path = require('path');
const { SKILLS_SRC } = require('./paths');
const { listFiles } = require('./fsutil');
const { UserError } = require('./errors');

// Read the YAML frontmatter of a SKILL.md. Supports the subset the Agent Skills format uses:
// top-level "key: value" pairs and one nested map (e.g. "metadata:").
function parseFrontmatter(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!m) return {};
  const data = {};
  let parent = null;
  for (const raw of m[1].split(/\r?\n/)) {
    if (!raw.trim() || raw.trim().startsWith('#')) continue;
    const nested = /^\s+([\w.-]+):\s*(.*)$/.exec(raw);
    const top = /^([\w.-]+):\s*(.*)$/.exec(raw);
    if (top) {
      const value = unquote(top[2]);
      if (value === '') {
        parent = top[1];
        data[parent] = {};
      } else {
        parent = null;
        data[top[1]] = value;
      }
    } else if (nested && parent) {
      data[parent][nested[1]] = unquote(nested[2]);
    }
  }
  return data;
}

function unquote(v) {
  v = v.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    return v.slice(1, -1);
  }
  return v;
}

function readSkillMeta(skillDir) {
  const file = path.join(skillDir, 'SKILL.md');
  if (!fs.existsSync(file)) return null;
  const fm = parseFrontmatter(fs.readFileSync(file, 'utf8'));
  return {
    name: fm.name || path.basename(skillDir),
    description: fm.description || '',
    version: (fm.metadata && fm.metadata.version) || null,
  };
}

// Every skill shipped in this package: { name, description, version, dir, files[] }.
function availableSkills() {
  if (!fs.existsSync(SKILLS_SRC)) return [];
  return fs
    .readdirSync(SKILLS_SRC, { withFileTypes: true })
    .filter((e) => e.isDirectory() && e.name.startsWith('sk-'))
    .map((e) => {
      const dir = path.join(SKILLS_SRC, e.name);
      const meta = readSkillMeta(dir);
      return meta && { ...meta, name: e.name, dir, files: listFiles(dir) };
    })
    .filter(Boolean)
    .sort((a, b) => a.name.localeCompare(b.name));
}

// Turn "--skills sk-api,sk-auth" into skill objects. sk-help is always included.
function selectSkills(skillsFlag) {
  const all = availableSkills();
  if (!skillsFlag) return all;
  const byName = new Map(all.map((s) => [s.name, s]));
  const wanted = new Set(
    skillsFlag
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => (s.startsWith('sk-') ? s : `sk-${s}`))
  );
  wanted.add('sk-help');
  const unknown = [...wanted].filter((n) => !byName.has(n));
  if (unknown.length) {
    throw new UserError(
      `Unknown skill(s): ${unknown.join(', ')}`,
      `Available: ${all.map((s) => s.name).join(', ')}`
    );
  }
  return [...wanted].map((n) => byName.get(n)).sort((a, b) => a.name.localeCompare(b.name));
}

module.exports = { parseFrontmatter, readSkillMeta, availableSkills, selectSkills };
