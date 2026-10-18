'use strict';

const { parseArgs } = require('./args');
const { checkEntitlement } = require('./gate');
const { KIT_VERSION } = require('./version');
const { UserError } = require('./errors');

const COMMANDS = {
  init: () => require('./commands/init'),
  update: () => require('./commands/update'),
  list: () => require('./commands/list'),
  ls: () => require('./commands/list'),
  skills: () => require('./commands/skills'),
  catalog: () => require('./commands/skills'),
  doctor: () => require('./commands/doctor'),
  help: () => require('./commands/help'),
};

async function main(argv) {
  const { _: positional, flags } = parseArgs(argv);
  if (flags.version) {
    console.log(KIT_VERSION);
    return 0;
  }
  const name = positional[0] || 'help';
  if (flags.help || name === 'help') return COMMANDS.help()(flags);
  if (!COMMANDS[name]) {
    throw new UserError(`Unknown command "${name}"`, 'Run "securitykit help" for usage.');
  }
  if (positional.length > 1) {
    throw new UserError(`Unexpected argument "${positional[1]}"`, 'Run "securitykit help" for usage.');
  }

  const gate = await checkEntitlement(name, { flags });
  if (!gate.ok) throw new UserError(gate.message || 'SecurityKit license check failed.', gate.hint);

  return COMMANDS[name]()(flags);
}

module.exports = { main };
