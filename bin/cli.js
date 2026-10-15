#!/usr/bin/env node
'use strict';

const { main } = require('../src/main');

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (err) => {
    const log = require('../src/log');
    if (err && err.userError) {
      log.error(err.message);
      if (err.hint) log.dim('  ' + err.hint);
    } else {
      log.error('Unexpected error: ' + (err && err.stack ? err.stack : err));
      log.dim('  Please report this at https://github.com/getsecuritykit/kit/issues');
    }
    process.exitCode = 1;
  }
);
