'use strict';

const { c } = require('../log');
const { KIT_VERSION } = require('../version');

const TEXT = () => `
${c.bold('SecurityKit')} ${KIT_VERSION} - security skills for AI coding agents

${c.bold('Usage')}
  npx github:getsecuritykit/kit <command> [options]

${c.bold('Commands')}
  init      Install skills into this project
  update    Update installed skills; files you edited are kept and listed
  list      Show installed skills and versions
  doctor    Check Node, Python 3, Semgrep and skill locations
  help      Show this help

${c.bold('Options')}
  --kit claude|codex|both   Target agent (default: detect .claude/ or .codex/, else ask)
  --dir <path>              Project directory (default: current directory)
  --skills sk-api,...       Install only these skills (init; sk-help is always included)
  --force                   Overwrite files you edited
  --dry-run                 Show what would change without writing (init, update)
  --yes, -y                 Do not prompt; install for both agents if none detected
  --json                    Machine-readable output (list)
  --version, -v             Print version

${c.bold('In your agent')}
  /sk-help                  List all SecurityKit commands
  /sk-api                   Audit API security, errors and tests

Docs: https://github.com/getsecuritykit/kit#readme
`;

async function help() {
  console.log(TEXT());
  return 0;
}

module.exports = help;
