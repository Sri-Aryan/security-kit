'use strict';

// Minimal coloured output with no dependencies.
// Colours are disabled when stdout is not a TTY or NO_COLOR is set; FORCE_COLOR re-enables them.

function colorEnabled() {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== '0') return true;
  return Boolean(process.stdout.isTTY);
}

const CODES = { red: 31, green: 32, yellow: 33, blue: 34, cyan: 36, gray: 90, bold: 1 };

function paint(name, text) {
  if (!colorEnabled()) return String(text);
  const close = name === 'bold' ? 22 : 39;
  return `\u001b[${CODES[name]}m${text}\u001b[${close}m`;
}

const c = {};
for (const name of Object.keys(CODES)) c[name] = (t) => paint(name, t);

module.exports = {
  c,
  info: (msg) => console.log(msg),
  ok: (msg) => console.log(`${c.green('✔')} ${msg}`),
  warn: (msg) => console.log(`${c.yellow('!')} ${msg}`),
  error: (msg) => console.error(`${c.red('✖')} ${msg}`),
  dim: (msg) => console.log(c.gray(msg)),
  heading: (msg) => console.log(`\n${c.bold(msg)}`),
};
