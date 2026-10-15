'use strict';

const log = require('./log');
const { c } = log;

// Print the outcome of a planSync/applySync run in a way the user can act on.
function printSyncResult(actions, { dryRun } = {}) {
  const verb = dryRun ? 'would be' : '';
  const by = (t) => actions.filter((a) => a.type === t);
  const lines = [
    ['add', 'added'],
    ['update', 'updated'],
    ['overwrite', 'overwritten (--force)'],
    ['remove', 'removed (no longer shipped)'],
    ['same', 'already up to date'],
  ];
  for (const [type, label] of lines) {
    const n = by(type).length;
    if (n) log.info(`  ${n} file(s) ${verb ? verb + ' ' : ''}${label}`);
  }

  const skipped = by('skip');
  if (skipped.length) {
    log.warn(`${skipped.length} file(s) you edited were left unchanged:`);
    for (const a of skipped) log.info(`    ${c.yellow(a.key)}`);
    log.dim('  Re-run with --force to overwrite them, or merge the changes by hand.');
  }
  const kept = by('keep-removed');
  if (kept.length) {
    log.warn(`${kept.length} file(s) are no longer shipped but you edited them, so they were kept:`);
    for (const a of kept) log.info(`    ${c.yellow(a.key)}`);
  }
}

module.exports = { printSyncResult };
