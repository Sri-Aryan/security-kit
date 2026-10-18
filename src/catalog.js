'use strict';

const fs = require('fs');
const path = require('path');
const { SKILLS_SRC } = require('./paths');
const { availableSkills } = require('./skills');

// skills/catalog.json groups the skills and gives each a one-line summary. It is the single source for
// `securitykit skills`, /sk-help and the README. Skills missing from it still show up, under "Other".
function loadCatalog() {
  const file = path.join(SKILLS_SRC, 'catalog.json');
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const shipped = new Map(availableSkills().map((s) => [s.name, s]));
  const listed = new Set();
  const groups = raw.groups.map((g) => ({
    id: g.id,
    title: g.title,
    blurb: g.blurb,
    skills: g.skills
      .filter((s) => shipped.has(s.name))
      .map((s) => {
        listed.add(s.name);
        return { name: s.name, summary: s.summary, version: shipped.get(s.name).version };
      }),
  }));
  const other = [...shipped.values()].filter((s) => !listed.has(s.name));
  if (other.length) {
    groups.push({
      id: 'other', title: 'Other', blurb: '',
      skills: other.map((s) => ({ name: s.name, summary: firstSentence(s.description), version: s.version })),
    });
  }
  return groups.filter((g) => g.skills.length);
}

function firstSentence(text) {
  const s = String(text || '').split(/(?<=\.)\s/)[0];
  return s.length > 90 ? `${s.slice(0, 87)}...` : s;
}

module.exports = { loadCatalog };
