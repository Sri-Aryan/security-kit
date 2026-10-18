'use strict';

// CLI tests: init, update, list, doctor and the manifest, each in a fresh temp project.
// Run with: node --test tests/  (or npm test)

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const REPO = path.resolve(__dirname, '..');

function tmpdir(prefix = 'sk-cli-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// Copy the kit (bin, src, skills, package.json) so a test can simulate a new release
// by editing the copy's skills/ folder.
function copyKit() {
  const dir = tmpdir('sk-kit-');
  for (const item of ['bin', 'src', 'skills', 'package.json']) {
    fs.cpSync(path.join(REPO, item), path.join(dir, item), { recursive: true });
  }
  return dir;
}

// Plain output for assertions. FORCE_COLOR would override NO_COLOR, so drop it.
// SECURITYKIT_HOME stands in for the home folder, so global installs never touch the real one.
const FAKE_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'sk-home-'));
const ENV = { ...process.env, NO_COLOR: '1', SECURITYKIT_HOME: FAKE_HOME };
delete ENV.FORCE_COLOR;

function run(args, { kit = REPO, cwd } = {}) {
  const r = spawnSync(process.execPath, [path.join(kit, 'bin', 'cli.js'), ...args], {
    encoding: 'utf8',
    cwd: cwd || os.tmpdir(),
    env: ENV,
    stdio: ['ignore', 'pipe', 'pipe'], // non-TTY: the CLI must never prompt
  });
  return { code: r.status, out: r.stdout + r.stderr };
}

const sha = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const readManifest = (dir) => JSON.parse(fs.readFileSync(path.join(dir, '.securitykit', 'manifest.json'), 'utf8'));
const skillFile = (dir, kit, ...p) => path.join(dir, `.${kit}`, 'skills', ...p);

test('init --kit claude copies all skills and writes a manifest with correct hashes', () => {
  const dir = tmpdir();
  const r = run(['init', '--kit', 'claude', '--dir', dir]);
  assert.equal(r.code, 0, r.out);
  assert.ok(fs.existsSync(skillFile(dir, 'claude', 'sk-api', 'SKILL.md')));
  assert.ok(fs.existsSync(skillFile(dir, 'claude', 'sk-api', 'scripts', 'discover_routes.py')));
  assert.ok(fs.existsSync(skillFile(dir, 'claude', 'sk-help', 'SKILL.md')));
  assert.ok(!fs.existsSync(path.join(dir, '.codex')));

  const m = readManifest(dir);
  assert.equal(m.kitVersion, require('../package.json').version);
  assert.deepEqual(m.kits, ['claude']);
  assert.ok(m.skills['sk-api'] && m.skills['sk-help']);
  const keys = Object.keys(m.files);
  assert.ok(keys.length > 5);
  for (const key of keys) {
    assert.ok(!key.includes('\\'), `manifest key uses forward slashes: ${key}`);
    assert.equal(m.files[key], sha(path.join(dir, ...key.split('/'))), key);
  }
});

test('init with no options installs every skill for every agent in the home folder, without asking', () => {
  const home = tmpdir('sk-home-');
  const cwd = tmpdir();
  const r = spawnSync(process.execPath, [path.join(REPO, 'bin', 'cli.js'), 'init'], {
    encoding: 'utf8', cwd, env: { ...ENV, SECURITYKIT_HOME: home }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  for (const kit of ['claude', 'codex', 'agents']) {
    assert.ok(fs.existsSync(skillFile(home, kit, 'sk-api', 'SKILL.md')), `${kit} missing`);
    assert.ok(fs.existsSync(skillFile(home, kit, 'sk-audit', 'SKILL.md')), `${kit} missing sk-audit`);
  }
  const m = readManifest(home);
  assert.deepEqual(m.kits, ['agents', 'claude', 'codex']);
  assert.equal(m.scope, 'global');
  assert.equal(Object.keys(m.skills).length, require('../src/skills').availableSkills().length);
  assert.deepEqual(fs.readdirSync(cwd), [], 'the current project is left untouched');
  assert.match(r.stdout, /~\/\.agents\/skills/);
});

test('init --project installs into the current project; list and update follow the same scope', () => {
  const home = tmpdir('sk-home-');
  const cwd = tmpdir();
  const env = { ...ENV, SECURITYKIT_HOME: home };
  const cli = (args) => spawnSync(process.execPath, [path.join(REPO, 'bin', 'cli.js'), ...args], {
    encoding: 'utf8', cwd, env, stdio: ['ignore', 'pipe', 'pipe'],
  });
  assert.equal(cli(['init', '--project']).status, 0);
  assert.ok(fs.existsSync(skillFile(cwd, 'agents', 'sk-api', 'SKILL.md')));
  assert.equal(readManifest(cwd).scope, 'project');
  assert.deepEqual(fs.readdirSync(home), [], 'nothing global was written');
  assert.match(cli(['list', '-p']).stdout, /Installed SecurityKit .* in /);
  assert.match(cli(['list']).stdout, /not installed for your user/);
  assert.equal(cli(['update', '--project']).status, 0);
});

test('init --kit narrows the agent folders', () => {
  const dir = tmpdir();
  const r = run(['init', '--kit', 'codex,agents', '--dir', dir]);
  assert.equal(r.code, 0, r.out);
  assert.ok(fs.existsSync(skillFile(dir, 'codex', 'sk-api', 'SKILL.md')));
  assert.ok(fs.existsSync(skillFile(dir, 'agents', 'sk-api', 'SKILL.md')));
  assert.ok(!fs.existsSync(path.join(dir, '.claude')));
  assert.deepEqual(readManifest(dir).kits, ['agents', 'codex']);
});

test('init --skills installs only the named skills plus sk-help', () => {
  const dir = tmpdir();
  const r = run(['init', '--kit', 'claude', '--skills', 'api', '--dir', dir]);
  assert.equal(r.code, 0, r.out);
  assert.deepEqual(Object.keys(readManifest(dir).skills).sort(), ['sk-api', 'sk-help']);
});

test('init rejects unknown skills, kits, options and commands', () => {
  const dir = tmpdir();
  assert.match(run(['init', '--kit', 'claude', '--skills', 'sk-nope', '--dir', dir]).out, /Unknown skill\(s\): sk-nope/);
  assert.match(run(['init', '--kit', 'vim', '--dir', dir]).out, /Invalid --kit "vim"/);
  assert.match(run(['init', '--bogus']).out, /Unknown option --bogus/);
  const r = run(['explode']);
  assert.equal(r.code, 1);
  assert.match(r.out, /Unknown command "explode"/);
  assert.match(run(['init', '--dir', path.join(dir, 'missing')]).out, /does not exist/);
});

test('init --dry-run writes nothing', () => {
  const dir = tmpdir();
  const r = run(['init', '--kit', 'claude', '--dry-run', '--dir', dir]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /would be added/);
  assert.deepEqual(fs.readdirSync(dir), []);
});

test('re-running init is idempotent and keeps user edits unless --force', () => {
  const dir = tmpdir();
  run(['init', '--kit', 'claude', '--dir', dir]);
  const again = run(['init', '--kit', 'claude', '--dir', dir]);
  assert.match(again.out, /already up to date/);
  assert.doesNotMatch(again.out, /added/);

  const target = skillFile(dir, 'claude', 'sk-api', 'checklist.md');
  fs.appendFileSync(target, '\n- my custom check\n');
  const kept = run(['init', '--kit', 'claude', '--dir', dir]);
  assert.match(kept.out, /1 file\(s\) you edited were left unchanged/);
  assert.match(fs.readFileSync(target, 'utf8'), /my custom check/);

  const forced = run(['init', '--kit', 'claude', '--force', '--dir', dir]);
  assert.match(forced.out, /overwritten/);
  assert.doesNotMatch(fs.readFileSync(target, 'utf8'), /my custom check/);
});

test('update applies new versions, skips edited files, removes dropped files', () => {
  const kit = copyKit();
  const dir = tmpdir();
  assert.equal(run(['init', '--kit', 'both', '--dir', dir], { kit }).code, 0);

  // User edits one installed file.
  const edited = skillFile(dir, 'claude', 'sk-api', 'SKILL.md');
  fs.appendFileSync(edited, '\nMy team note.\n');

  // New release: SKILL.md and the template change, a file is added, another is removed.
  const src = path.join(kit, 'skills', 'sk-api');
  fs.appendFileSync(path.join(src, 'SKILL.md'), '\n<!-- v0.2 -->\n');
  fs.appendFileSync(path.join(src, 'templates', 'report.md'), '\n<!-- v0.2 -->\n');
  fs.writeFileSync(path.join(src, 'NEW_FILE.md'), 'new in 0.2\n');
  fs.rmSync(path.join(src, 'scripts', 'semgrep_to_candidates.py'));

  const r = run(['update', '--dir', dir], { kit });
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /you edited were left unchanged/);
  assert.match(r.out, /\.claude\/skills\/sk-api\/SKILL\.md/);

  // Edited file kept for Claude; same file updated for Codex (untouched there).
  assert.match(fs.readFileSync(edited, 'utf8'), /My team note/);
  assert.doesNotMatch(fs.readFileSync(edited, 'utf8'), /v0\.2/);
  assert.match(fs.readFileSync(skillFile(dir, 'codex', 'sk-api', 'SKILL.md'), 'utf8'), /v0\.2/);
  // Unedited changed file updated in both.
  for (const k of ['claude', 'codex']) {
    assert.match(fs.readFileSync(skillFile(dir, k, 'sk-api', 'templates', 'report.md'), 'utf8'), /v0\.2/);
    assert.ok(fs.existsSync(skillFile(dir, k, 'sk-api', 'NEW_FILE.md')));
    assert.ok(!fs.existsSync(skillFile(dir, k, 'sk-api', 'scripts', 'semgrep_to_candidates.py')));
  }

  // Manifest still records the OLD hash for the skipped file, so it stays "edited".
  const m = readManifest(dir);
  assert.notEqual(m.files['.claude/skills/sk-api/SKILL.md'], sha(edited));
  assert.equal(m.files['.codex/skills/sk-api/SKILL.md'], sha(skillFile(dir, 'codex', 'sk-api', 'SKILL.md')));
  assert.ok(!('.claude/skills/sk-api/scripts/semgrep_to_candidates.py' in m.files));

  // --force takes the new version.
  const forced = run(['update', '--force', '--dir', dir], { kit });
  assert.equal(forced.code, 0, forced.out);
  assert.match(fs.readFileSync(edited, 'utf8'), /v0\.2/);
});

test('update keeps a dropped file the user edited', () => {
  const kit = copyKit();
  const dir = tmpdir();
  run(['init', '--kit', 'claude', '--dir', dir], { kit });
  const f = skillFile(dir, 'claude', 'sk-api', 'scripts', 'dynamic_tests.py');
  fs.appendFileSync(f, '\n# local tweak\n');
  fs.rmSync(path.join(kit, 'skills', 'sk-api', 'scripts', 'dynamic_tests.py'));
  const r = run(['update', '--dir', dir], { kit });
  assert.match(r.out, /no longer shipped but you edited them/);
  assert.ok(fs.existsSync(f));
});

test('update without an install explains how to install', () => {
  const r = run(['update', '--dir', tmpdir()]);
  assert.equal(r.code, 1);
  assert.match(r.out, /not installed in this project/);
});

test('list shows versions and edited files; --json is machine-readable', () => {
  const dir = tmpdir();
  run(['init', '--kit', 'claude', '--dir', dir]);
  fs.appendFileSync(skillFile(dir, 'claude', 'sk-help', 'SKILL.md'), 'x');
  const r = run(['list', '--dir', dir]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /sk-api\s+0\.1\.0/);
  assert.match(r.out, /claude: 1 edited/);

  const j = JSON.parse(run(['list', '--json', '--dir', dir]).out);
  const help = j.installed.skills.find((s) => s.name === 'sk-help');
  assert.equal(help.status.claude.modified, 1);
  assert.ok(j.available.some((s) => s.name === 'sk-api'));
});

test('list in an empty project says how to install', () => {
  const r = run(['list', '--dir', tmpdir()]);
  assert.equal(r.code, 0);
  assert.match(r.out, /not installed/);
});

test('doctor passes on a good install and flags misplaced skills', () => {
  const dir = tmpdir();
  run(['init', '--kit', 'claude', '--dir', dir]);
  const ok = run(['doctor', '--dir', dir]);
  assert.match(ok.out, /Node \d+/);
  assert.match(ok.out, /\.claude[\\/]skills[\\/]sk-api[\\/]SKILL\.md/);

  fs.mkdirSync(path.join(dir, '.claude', 'sk-api'));
  const bad = run(['doctor', '--dir', dir]);
  assert.equal(bad.code, 1);
  assert.match(bad.out, /is in the wrong place/);

  fs.rmSync(skillFile(dir, 'claude', 'sk-help', 'SKILL.md'));
  assert.match(run(['doctor', '--dir', dir]).out, /SKILL\.md is missing/);
});

test('help and --version', () => {
  assert.match(run(['help']).out, /Commands/);
  assert.match(run([]).out, /securitykit|SecurityKit/);
  assert.equal(run(['--version']).out.trim(), require('../package.json').version);
});

test('every shipped skill has valid frontmatter with an sk- name and description', () => {
  const { availableSkills } = require('../src/skills');
  const skills = availableSkills();
  assert.ok(skills.length >= 2);
  for (const s of skills) {
    assert.match(s.name, /^sk-[a-z0-9-]+$/);
    assert.ok(s.description.length > 40, `${s.name} needs a description that says when to use it`);
    assert.ok(s.description.length <= 1024, `${s.name} description exceeds 1024 chars`);
    const fm = require('../src/skills').parseFrontmatter(fs.readFileSync(path.join(s.dir, 'SKILL.md'), 'utf8'));
    assert.equal(fm.name, s.name, 'frontmatter name must match the folder name');
  }
});

test('catalog lists every shipped skill exactly once', () => {
  const { availableSkills } = require('../src/skills');
  const catalog = JSON.parse(fs.readFileSync(path.join(REPO, 'skills', 'catalog.json'), 'utf8'));
  const listed = catalog.groups.flatMap((g) => g.skills.map((s) => s.name));
  assert.deepEqual([...listed].sort(), availableSkills().map((s) => s.name).sort());
  assert.equal(new Set(listed).size, listed.length, 'a skill is listed twice');
  for (const g of catalog.groups) {
    for (const s of g.skills) assert.ok(s.summary.length <= 90, `${s.name} summary is longer than one line`);
  }
});

test('skills shows every skill grouped; --group filters; --json is machine-readable', () => {
  const r = run(['skills']);
  assert.equal(r.code, 0, r.out);
  const catalog = JSON.parse(fs.readFileSync(path.join(REPO, 'skills', 'catalog.json'), 'utf8'));
  for (const g of catalog.groups) {
    assert.match(r.out, new RegExp(`── ${g.title.replace(/[&]/g, '\$&')} `));
    for (const s of g.skills) assert.ok(r.out.includes(`/${s.name} `), `${s.name} missing from output`);
  }
  // Groups appear in catalog order.
  const positions = catalog.groups.map((g) => r.out.indexOf(`── ${g.title} `));
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b));

  const ai = run(['skills', '--group', 'ai']);
  assert.equal(ai.code, 0);
  assert.ok(ai.out.includes('/sk-agents') && !ai.out.includes('/sk-api '));

  const bad = run(['skills', '--group', 'nope']);
  assert.notEqual(bad.code, 0);
  assert.match(bad.out, /workflows/);

  const json = JSON.parse(run(['skills', '--json']).out);
  assert.equal(json.groups.length, catalog.groups.length);
  assert.equal(json.groups[0].skills[0].installed, null);
});

test('skills marks installed skills in an installed project', () => {
  const dir = tmpdir();
  assert.equal(run(['init', '--kit', 'claude', '--skills', 'sk-api', '--dir', dir]).code, 0);
  const json = JSON.parse(run(['skills', '--json', '--dir', dir]).out);
  const all = json.groups.flatMap((g) => g.skills);
  assert.equal(all.find((s) => s.name === 'sk-api').installed, true);
  assert.equal(all.find((s) => s.name === 'sk-xss').installed, false);
});

test('README and sk-help show the same grouped skill list as the catalog', () => {
  const catalog = JSON.parse(fs.readFileSync(path.join(REPO, 'skills', 'catalog.json'), 'utf8'));
  for (const file of ['README.md', path.join('skills', 'sk-help', 'SKILL.md')]) {
    const text = fs.readFileSync(path.join(REPO, file), 'utf8');
    for (const g of catalog.groups) {
      assert.ok(text.includes(`### ${g.title}`), `${file}: group ${g.title} missing (run python tools/gen_catalog_docs.py)`);
      for (const s of g.skills) {
        assert.ok(text.includes(`| \`/${s.name}\` | ${s.summary} |`), `${file}: ${s.name} out of date (run python tools/gen_catalog_docs.py)`);
      }
    }
  }
});
