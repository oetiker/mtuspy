// repo-infra: workflow-lib v9
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const nfpm = require('./nfpm.js');

const TARGETS = 'x86_64-unknown-linux-musl aarch64-unknown-linux-musl';
const BOTH = '{"deb": {}, "rpm": {}}';
// Shaped like mtuspy's nfpm.yaml: names in a comment, in top-level scalars
// and in the contents paths nfpm itself does not expand.
const CONFIG = [
  '# Filled in by ri-release-nfpm: VERSION, MTIME, ARCH and STAGE.',
  'name: tool',
  'arch: "${ARCH}"',
  'version: "${VERSION}"',
  'mtime: "${MTIME}"',
  'contents:',
  '  - src: ${STAGE}/tool',
  '    dst: /usr/bin/tool',
  '',
].join('\n');
const ARCH = { 'x86_64-unknown-linux-musl': ['amd64', 'x86_64'],
  'aarch64-unknown-linux-musl': ['arm64', 'aarch64'] };

// A checkout as download-artifact leaves it, and stand-ins for git, tar,
// nfpm, dpkg-deb and rpm. `archives` maps a target to the file names in its
// artifact; `tops` is what one archive unpacks to and `man` what its
// tool/man/ holds; `name` and `version` shape what the stand-in nfpm writes
// and what the read-back reports.
function fakeIo({
  config = CONFIG, archives, tops = ['tool'], man = [], name, version = (v) => v, files = 2,
} = {}) {
  const dirs = new Map();
  const written = new Map();
  const calls = [];
  const add = (dir, entry) => {
    if (!dirs.has(dir)) dirs.set(dir, new Set());
    if (entry !== undefined) dirs.get(dir).add(entry);
  };
  const folders = archives || Object.fromEntries(
    TARGETS.split(' ').map((t) => [t, [`tool-1.2.3-${t}.tar.gz`]]));
  for (const [target, names] of Object.entries(folders)) {
    for (const n of names) add(`archives/release-asset-${target}`, n);
  }
  const io = {
    isFile: (path) => path === 'nfpm.yaml' && config !== null,
    isDir: (path) => /\/stage\/[^/]+\/tool$/.test(path),
    read: () => config,
    write: (path, text) => written.set(path, text),
    mkdir: (path) => add(path),
    list: (path) => [...(dirs.get(path) || [])].sort(),
    exec: (command, args, options) => {
      calls.push({ command, args, env: options && options.env });
      if (command === 'git') return '1700000000\n';
      if (command === 'tar') {
        for (const top of tops) add(args[3], top);
        for (const page of man) add(`${args[3]}/tool/man`, page);
        return '';
      }
      if (command === 'gzip') return '';
      if (command === 'nfpm') {
        const { PACKAGER, ARCH: arch, VERSION } = options.env;
        const rpmArch = Object.values(ARCH).find((pair) => pair[0] === arch)[1];
        const file = name ? name(PACKAGER, arch)
          : PACKAGER === 'deb' ? `tool_${VERSION}-1_${arch}.deb`
            : `tool-${VERSION}-1.${rpmArch}.rpm`;
        add('packages', file);
        return null;
      }
      if (command === 'dpkg-deb' && args[0] === '--field') return `${version('1.2.3-1')}\n`;
      if (command === 'dpkg-deb') {
        return ['drwxr-xr-x root/root 0 ./usr/',
          ...Array.from({ length: files }, (_, i) => `-rwxr-xr-x root/root 1 ./usr/bin/f${i}`),
        ].join('\n');
      }
      if (command === 'rpm' && args[1] === '--queryformat') return version('1.2.3');
      if (command === 'rpm') {
        return Array.from({ length: files }, (_, i) => `/usr/bin/f${i}`).join('\n');
      }
      throw new Error(`unexpected command ${command}`);
    },
  };
  return { io, written, calls };
}

function env(overrides = {}) {
  return { VERSION: '1.2.3', CONFIG: 'nfpm.yaml', PACKAGERS: BOTH, ARCHIVES: TARGETS,
    RUNNER_TEMP: '/t', ...overrides };
}

// The step hands error.message to core.setFailed, which prints one
// ::error:: line. A message with a line break or a stack frame would print a
// trace instead of naming the input.
function refusal(fn, expected) {
  assert.throws(fn, (error) => {
    assert.match(error.message, expected);
    assert.doesNotMatch(error.message, /\n/);
    return true;
  });
}

test('four packages are built and each is read back', () => {
  const { io, calls } = fakeIo();
  assert.deepEqual(nfpm.run(env(), io), [
    'tool_1.2.3-1_amd64.deb: version 1.2.3-1, 2 files',
    'tool-1.2.3-1.x86_64.rpm: version 1.2.3, 2 files',
    'tool_1.2.3-1_arm64.deb: version 1.2.3-1, 2 files',
    'tool-1.2.3-1.aarch64.rpm: version 1.2.3, 2 files',
  ]);
  const runs = calls.filter((c) => c.command === 'nfpm');
  assert.deepEqual(runs.map((c) => [c.env.PACKAGER, c.env.ARCH, c.env.TARGET]), [
    ['deb', 'amd64', 'x86_64-unknown-linux-musl'],
    ['rpm', 'amd64', 'x86_64-unknown-linux-musl'],
    ['deb', 'arm64', 'aarch64-unknown-linux-musl'],
    ['rpm', 'arm64', 'aarch64-unknown-linux-musl'],
  ]);
  assert.equal(runs[0].env.SOURCE_DATE_EPOCH, '1700000000');
  assert.equal(runs[0].env.MTIME, '2023-11-14T22:13:20Z');
  assert.equal(runs[0].env.STAGE, '/t/stage/x86_64-unknown-linux-musl/tool');
});

test('the man pages of each archive are gzipped once, before nfpm runs', () => {
  const { io, calls } = fakeIo({ man: ['tool.1', 'toold.8', 'notes.txt'] });
  nfpm.run(env(), io);
  const order = calls.map((c) => c.command).filter((c) => c === 'gzip' || c === 'nfpm');
  assert.deepEqual(order, ['gzip', 'nfpm', 'nfpm', 'gzip', 'nfpm', 'nfpm']);
  assert.deepEqual(calls.find((c) => c.command === 'gzip').args, ['-9n', '--',
    '/t/stage/x86_64-unknown-linux-musl/tool/man/tool.1',
    '/t/stage/x86_64-unknown-linux-musl/tool/man/toold.8']);
});

test('an archive without man pages runs no gzip', () => {
  const { io, calls } = fakeIo();
  nfpm.run(env(), io);
  assert.equal(calls.filter((c) => c.command === 'gzip').length, 0);
});

test('every name in the config is filled in, comments and contents paths too', () => {
  const { io, written } = fakeIo();
  nfpm.run(env(), io);
  const text = written.get('/t/nfpm-x86_64-unknown-linux-musl-deb.yaml');
  assert.doesNotMatch(text, /\$\{/);
  assert.match(text, /^arch: "amd64"$/m);
  assert.match(text, /^mtime: "2023-11-14T22:13:20Z"$/m);
  assert.match(text, /src: \/t\/stage\/x86_64-unknown-linux-musl\/tool\/tool$/m);
});

test('a packagers value reaches the config of its packager only', () => {
  const config = `${CONFIG}homepage: \${HOMEPAGE}\n`;
  const { io, written } = fakeIo({ config });
  nfpm.run(env({ PACKAGERS: '{"deb": {"HOMEPAGE": "https://d"}, "rpm": {"HOMEPAGE": "https://r"}}' }), io);
  assert.match(written.get('/t/nfpm-x86_64-unknown-linux-musl-deb.yaml'), /homepage: https:\/\/d$/m);
  assert.match(written.get('/t/nfpm-x86_64-unknown-linux-musl-rpm.yaml'), /homepage: https:\/\/r$/m);
});

for (const [packagers, expected] of [
  ['{deb}', /^packagers is not JSON: /],
  ['{\n"deb": {},\n"rpm": x\n}', /^packagers is not JSON: /],
  ['{"deb": "x"}', /^packagers must be a JSON object/],
  ['{}', /^packagers must be a JSON object/],
  ['[]', /^packagers must be a JSON object/],
  ['{"deb": {"NAME": 1}}', /^packagers must be a JSON object/],
  ['{"apk": {}}', /^packagers names apk; ri-release-nfpm builds deb and rpm$/],
  ['{"deb": {"VERSION": "9"}}', /^packagers\.deb sets VERSION, which ri-release-nfpm sets itself$/],
  ['{"rpm": {"STAGE": "/", "ARCH": "noarch"}}', /^packagers\.rpm sets ARCH, STAGE, /],
]) {
  test(`packagers ${packagers} fails with one line naming the input`, () => {
    const { io, calls } = fakeIo();
    refusal(() => nfpm.run(env({ PACKAGERS: packagers }), io), expected);
    assert.deepEqual(calls, [], 'nothing runs before the inputs are checked');
  });
}

for (const [archives, expected] of [
  ['', /^archives names no target$/],
  ['x86_64-unknown-illumos', /^no package architecture is known for x86_64-unknown-illumos; archives takes x86_64-unknown-linux-musl and aarch64-unknown-linux-musl$/],
  ['toString', /^no package architecture is known for toString;/],
]) {
  test(`archives "${archives}" fails`, () => {
    refusal(() => nfpm.run(env({ ARCHIVES: archives }), fakeIo().io), expected);
  });
}

test('a missing config fails naming it', () => {
  refusal(() => nfpm.run(env(), fakeIo({ config: null }).io), /^nfpm\.yaml does not exist$/);
});

test('a missing archive fails naming its artifact', () => {
  const { io } = fakeIo({ archives: { 'x86_64-unknown-linux-musl': ['tool-1.2.3-x86_64-unknown-linux-musl.tar.gz'] } });
  refusal(() => nfpm.run(env(), io),
    /^release-asset-aarch64-unknown-linux-musl holds 0 \.tar\.gz files; one is expected$/);
});

test('two archives in one artifact fail', () => {
  const { io } = fakeIo({ archives: {
    'x86_64-unknown-linux-musl': ['a.tar.gz', 'b.tar.gz'],
    'aarch64-unknown-linux-musl': ['c.tar.gz'] } });
  refusal(() => nfpm.run(env(), io), /^release-asset-x86_64-unknown-linux-musl holds 2 /);
});

test('an archive without one top folder fails', () => {
  refusal(() => nfpm.run(env(), fakeIo({ tops: ['tool', 'README.md'] }).io),
    /^tool-1\.2\.3-x86_64-unknown-linux-musl\.tar\.gz must hold one folder, the <bin>\/ of the archive layout$/);
});

test('a name nobody sets fails before nfpm runs', () => {
  const { io, calls } = fakeIo({ config: `${CONFIG}homepage: \${HOMEPAGE}\n# \${LATER}\n` });
  refusal(() => nfpm.run(env(), io),
    /^nfpm\.yaml uses \$\{HOMEPAGE\}, \$\{LATER\}, which neither ri-release-nfpm nor packagers sets$/);
  assert.equal(calls.filter((c) => c.command === 'nfpm').length, 0);
});

test('a package name ri-publish-gitea refuses fails', () => {
  const { io } = fakeIo({ name: (p, arch) => (p === 'deb' ? `Tool_1.2.3-1_${arch}.deb` : 'x.rpm') });
  refusal(() => nfpm.run(env({ PACKAGERS: '{"deb": {}}' }), io),
    /^Tool_1\.2\.3-1_amd64\.deb is not name_version_arch\.deb, the name ri-publish-gitea uploads$/);
  refusal(() => nfpm.run(env({ PACKAGERS: '{"rpm": {}}' }), fakeIo({ name: () => 'tool.rpm' }).io),
    /^tool\.rpm is not name-version-release\.arch\.rpm/);
});

test('a package carrying another version fails', () => {
  const { io } = fakeIo({ version: () => '0.1.3' });
  refusal(() => nfpm.run(env(), io), /^tool_1\.2\.3-1_amd64\.deb carries version 0\.1\.3, not 1\.2\.3$/);
});

test('a package holding no files fails', () => {
  refusal(() => nfpm.run(env(), fakeIo({ files: 0 }).io), /^tool_1\.2\.3-1_amd64\.deb holds no files$/);
});

test('a packagers value fills in the config but stays out of the environment of nfpm', () => {
  const { io, calls, written } = fakeIo({ config: `${CONFIG}# \${PATH}\n` });
  nfpm.run(env({ PACKAGERS: '{"deb": {"PATH": "x"}}', PATH: '/usr/bin' }), io);
  assert.match(written.get('/t/nfpm-x86_64-unknown-linux-musl-deb.yaml'), /^# x$/m);
  for (const call of calls.filter((c) => c.command === 'nfpm')) {
    assert.equal(call.env.PATH, '/usr/bin');
  }
});

test('rfc3339 drops the milliseconds', () => {
  assert.equal(nfpm.rfc3339('0'), '1970-01-01T00:00:00Z');
});
