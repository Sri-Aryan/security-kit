'use strict';

const log = require('../log');
const { c } = log;
const { resolveInstallRoot } = require('../paths');
const { readManifest } = require('../manifest');
const { loadCatalog } = require('../catalog');
const { KIT_VERSION } = require('../version');
const { UserError } = require('../errors');

const WIDTH = 78;

// Every shipped skill, grouped, with its one-line summary. Marks the ones installed in the project, if any.
async function skills(flags) {
  let groups = loadCatalog();
  if (flags.group) {
    const want = String(flags.group).toLowerCase();
    groups = groups.filter((g) => g.id === want || g.title.toLowerCase().startsWith(want));
    if (!groups.length) {
      throw new UserError(`No skill group "${flags.group}"`, `Groups: ${loadCatalog().map((g) => g.id).join(', ')}`);
    }
  }
  const root = resolveInstallRoot(flags);
  const manifest = readManifest(root.dir);
  const installed = manifest ? new Set(Object.keys(manifest.skills)) : null;

  if (flags.json) {
    console.log(JSON.stringify({
      kitVersion: KIT_VERSION,
      groups: groups.map((g) => ({
        ...g,
        skills: g.skills.map((s) => ({ ...s, installed: installed ? installed.has(s.name) : null })),
      })),
    }, null, 2));
    return 0;
  }

  const total = groups.reduce((n, g) => n + g.skills.length, 0);
  const nameWidth = Math.max(...groups.flatMap((g) => g.skills.map((s) => s.name.length))) + 3;
  log.heading(`SecurityKit ${KIT_VERSION}: ${total} skills in ${groups.length} group${groups.length === 1 ? '' : 's'}`);
  if (installed) log.dim(`  ${c.green('●')} installed ${root.scope === 'global' ? 'for all projects' : 'in this project'}   ${c.gray('○')} not installed`);

  for (const g of groups) {
    const title = ` ${g.title} `;
    console.log(`\n${c.cyan('──')}${c.bold(c.cyan(title))}${c.cyan('─'.repeat(Math.max(4, WIDTH - title.length - 2)))}`);
    if (g.blurb) log.dim(`  ${g.blurb}`);
    for (const s of g.skills) {
      const mark = installed ? (installed.has(s.name) ? `${c.green('●')} ` : `${c.gray('○')} `) : '';
      console.log(`  ${mark}${c.bold(`/${s.name}`.padEnd(nameWidth))}${s.summary}`);
    }
  }

  console.log('');
  log.dim('  Run a skill in your AI agent by typing its name, e.g. /sk-audit or /sk-review.');
  log.dim('  Not sure where to start? /sk-audit for the whole project, /sk-review before each merge.');
  if (!installed) log.dim('  Install for every agent and project: npx github:getsecuritykit/kit init');
  return 0;
}

module.exports = skills;
