'use strict';

const { c } = require('../log');
const { KIT_VERSION } = require('../version');

const TEXT = () => `
${c.bold('SecurityKit')} ${KIT_VERSION} - security skills for AI coding agents

${c.bold('Usage')}
  npx github:getsecuritykit/kit <command> [options]

${c.bold('Commands')}
  init      Install all skills for every agent, for all your projects (no questions asked)
  update    Update installed skills; files you edited are kept and listed
  skills    Show every skill, grouped, with a one-line description
  list      Show installed skills and versions
  doctor    Check Node, Python 3, Semgrep and skill locations
  help      Show this help

${c.bold('Where skills go')}
  Default (all projects)   ~/.claude/skills  ~/.codex/skills  ~/.agents/skills
  --project, -p            the same folders inside the current project instead
                           (commit them so your whole team gets the skills)

${c.bold('Options')}
  --project, -p             Install/update/list in the current project instead of your home folder
  --dir <path>              Like --project, for another project directory
  --kit <list>              Only some agent folders: claude, codex, agents (default: all)
  --skills sk-api,...       Install only these skills (init; sk-help is always included)
  --group <id>              Show one group only (skills), e.g. --group ai
  --force                   Overwrite files you edited
  --dry-run                 Show what would change without writing (init, update)
  --json                    Machine-readable output (skills, list)
  --version, -v             Print version

${c.bold('In your agent')}
  /sk-help                  What to run first for this project, and every command
  /sk-audit                 Audit the whole project and get one combined report
  /sk-review                Review the current change before you merge it
  /sk-fix                   Fix findings one by one, with your approval

Docs: https://github.com/getsecuritykit/kit#readme
`;

async function help() {
  console.log(TEXT());
  return 0;
}

module.exports = help;
