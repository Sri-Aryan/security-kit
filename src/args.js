'use strict';

const { UserError } = require('./errors');

// Flags that take a value. Everything else starting with -- is a boolean.
const VALUE_FLAGS = new Set(['kit', 'dir', 'skills', 'group']);
const BOOL_FLAGS = new Set(['force', 'project', 'help', 'version', 'json', 'dry-run']);
const SHORT = { h: 'help', v: 'version', f: 'force', p: 'project' };

function parseArgs(argv) {
  const out = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      let [name, value] = arg.slice(2).split(/=(.*)/s, 2);
      if (VALUE_FLAGS.has(name)) {
        if (value === undefined) {
          value = argv[++i];
          if (value === undefined || value.startsWith('-')) {
            throw new UserError(`--${name} needs a value`);
          }
        }
        out.flags[name] = value;
      } else if (BOOL_FLAGS.has(name)) {
        if (value !== undefined) throw new UserError(`--${name} does not take a value`);
        out.flags[name] = true;
      } else {
        throw new UserError(`Unknown option --${name}`, 'Run "securitykit help" for usage.');
      }
    } else if (/^-[a-z]$/i.test(arg)) {
      const name = SHORT[arg[1]];
      if (!name) throw new UserError(`Unknown option ${arg}`, 'Run "securitykit help" for usage.');
      out.flags[name] = true;
    } else {
      out._.push(arg);
    }
  }
  return out;
}

module.exports = { parseArgs };
