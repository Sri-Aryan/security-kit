'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const log = require('../log');
const { c } = log;
const { KIT_TARGETS, KITS, resolveProjectDir, skillsDirFor } = require('../paths');
const { readManifest } = require('../manifest');
const { availableSkills } = require('../skills');

// Run a command and return its first output line, or null if it is not available.
function probe(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', timeout: 20000, windowsHide: true });
  if (r.error || r.status !== 0) return null;
  const out = `${r.stdout || ''}${r.stderr || ''}`.trim();
  return out.split(/\r?\n/)[0] || null;
}

// Python 3 under any of its usual names. On Windows "python3" may be the Store stub, which fails the probe.
function findPython() {
  const candidates = process.platform === 'win32'
    ? [['python', ['--version']], ['py', ['-3', '--version']], ['python3', ['--version']]]
    : [['python3', ['--version']], ['python', ['--version']]];
  for (const [cmd, args] of candidates) {
    const out = probe(cmd, args);
    if (out && /Python 3\./.test(out)) return { cmd: [cmd, ...args.slice(0, -1)].join(' '), version: out };
  }
  return null;
}

async function doctor(flags) {
  const projectDir = resolveProjectDir(flags.dir);
  let failures = 0;
  const pass = (m) => log.ok(m);
  const fail = (m, hint) => {
    failures++;
    log.error(m);
    if (hint) log.dim(`    ${hint}`);
  };
  const warn = (m, hint) => {
    log.warn(m);
    if (hint) log.dim(`    ${hint}`);
  };

  log.heading('Tools');
  const major = Number(process.versions.node.split('.')[0]);
  if (major >= 18) pass(`Node ${process.versions.node}`);
  else fail(`Node ${process.versions.node} is too old`, 'SecurityKit needs Node 18 or newer.');

  const py = findPython();
  if (py) pass(`${py.version} (${py.cmd})`);
  else fail('Python 3 not found', 'Needed for route discovery and dynamic tests. Install from https://www.python.org/downloads/');

  const semgrep = probe('semgrep', ['--version']);
  if (semgrep) pass(`Semgrep ${semgrep}`);
  else warn('Semgrep not found (optional)', 'Static rules will be skipped and the agent reviews code by hand. Install: pip install semgrep');

  if (process.platform === 'win32') {
    const bash = probe('bash', ['--version']);
    if (bash) pass('bash available (for run_static.sh)');
    else warn('bash not found', 'Skills will use scripts\\run_static.ps1 instead.');
  }

  log.heading(`Project: ${projectDir}`);
  const manifest = readManifest(projectDir);
  if (!manifest) {
    warn('SecurityKit is not installed here', 'Run: npx github:getsecuritykit/kit init');
  } else {
    pass(`Manifest found (kit ${manifest.kitVersion}, agents: ${manifest.kits.join(', ') || 'none'})`);
    for (const kit of manifest.kits) {
      for (const name of Object.keys(manifest.skills)) {
        const skillMd = path.join(skillsDirFor(projectDir, kit), name, 'SKILL.md');
        const rel = path.relative(projectDir, skillMd);
        if (fs.existsSync(skillMd)) pass(`${rel}`);
        else fail(`${rel} is missing`, 'Run: npx github:getsecuritykit/kit update --force');
      }
    }
  }

  // Common mistake: skills copied one level too high (e.g. .claude/sk-api instead of .claude/skills/sk-api).
  const names = availableSkills().map((s) => s.name);
  for (const kit of KITS) {
    const root = path.join(projectDir, KIT_TARGETS[kit].root);
    for (const name of names) {
      const misplaced = path.join(root, name);
      if (fs.existsSync(misplaced)) {
        fail(
          `${path.relative(projectDir, misplaced)} is in the wrong place`,
          `${KIT_TARGETS[kit].label} only loads skills from ${path.relative(projectDir, skillsDirFor(projectDir, kit))}${path.sep}. Move it or re-run init.`
        );
      }
    }
  }

  log.info('');
  if (failures) log.error(`${failures} problem(s) found.`);
  else log.ok(c.green('All required checks passed.'));
  return failures ? 1 : 0;
}

module.exports = doctor;
module.exports.findPython = findPython;
