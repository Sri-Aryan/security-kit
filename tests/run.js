#!/usr/bin/env node
'use strict';

// Runs the whole suite: Node CLI tests, then Python tests (route discovery, Semgrep rules,
// detection coverage). Usage: node tests/run.js [--node-only]

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const TESTS = __dirname;
let failed = false;

const nodeTests = fs.readdirSync(TESTS).filter((f) => f.endsWith('.test.js')).map((f) => path.join(TESTS, f));
console.log(`\n== Node tests (${nodeTests.length} files)`);
const node = spawnSync(process.execPath, ['--test', ...nodeTests], { stdio: 'inherit' });
if (node.status !== 0) failed = true;

if (!process.argv.includes('--node-only')) {
  const candidates = process.platform === 'win32'
    ? [['python'], ['py', '-3'], ['python3']]
    : [['python3'], ['python']];
  const py = candidates.find(([cmd, ...pre]) => {
    const r = spawnSync(cmd, [...pre, '--version'], { encoding: 'utf8' });
    return r.status === 0 && /Python 3\./.test(r.stdout + r.stderr);
  });
  if (!py) {
    console.error('\nPython 3 not found: skipping Python tests');
    failed = true;
  } else {
    console.log('\n== Python tests');
    const [cmd, ...pre] = py;
    const r = spawnSync(cmd, [...pre, '-m', 'unittest', 'discover', '-s', TESTS, '-p', 'test_*.py', '-v'], {
      stdio: 'inherit',
      cwd: TESTS,
    });
    if (r.status !== 0) failed = true;
  }
}

process.exitCode = failed ? 1 : 0;
