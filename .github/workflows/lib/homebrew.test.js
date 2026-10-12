// repo-infra: workflow-lib v9
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const brew = require('./homebrew.js');

// The formula template of references/project-shape.md with its placeholders
// filled in; tests/test_release_homebrew.py holds the two to the same text.
const FORMULA = `# Homebrew formula for tool. This repository is its own tap.
#
# The release build rewrites the version line, the four sha256 lines by their
# marker comments and the bottle block between the BOTTLE markers. Keep the
# markers, and keep each url line directly above its sha256 line.
class Tool < Formula
  desc "A tool"
  homepage "https://github.com/owner/tool"
  version "0.0.0"
  license "MIT"

  # BOTTLE-START
  # BOTTLE-END

  on_macos do
    on_arm do
      url "https://github.com/owner/tool/releases/download/v#{version}/tool-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # mac-arm
    end
    on_intel do
      url "https://github.com/owner/tool/releases/download/v#{version}/tool-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # mac-x86
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/owner/tool/releases/download/v#{version}/tool-#{version}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # linux-x86
    end
    on_arm do
      url "https://github.com/owner/tool/releases/download/v#{version}/tool-#{version}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # linux-arm
    end
  end

  def install
    bin.install "tool"
    Dir["man/*.[1-9]"].each { |page| (man/"man#{page[-1]}").install page }
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tool --version")
  end
end
`;
const ENV = { BIN: 'tool', VERSION: '1.2.3', GITHUB_REPOSITORY: 'owner/tool', RUNNER_TEMP: '/t' };

// The shape `brew bottle --json --no-rebuild` writes: one entry per formula,
// the cellar on the bottle, the two file names on each tag.
function bottleJson(tag, sha, cellar) {
  const entry = { filename: `tool-1.2.3.${tag}.bottle.tar.gz`,
    local_filename: `tool--1.2.3.${tag}.bottle.tar.gz`, sha256: sha };
  if (cellar) entry.cellar = cellar;
  return { 'local/tool/tool': { formula: { name: 'tool', pkg_version: '1.2.3' },
    bottle: { cellar: 'any_skip_relocation', rebuild: 0, tags: { [tag]: entry } } } };
}
const ARM = bottleJson('arm64_sonoma', 'a'.repeat(64));
const INTEL = bottleJson('sequoia', 'b'.repeat(64));

function digest(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

// A checkout as the bottle and formula jobs see it: `files` maps a path,
// relative to /w, to its text.
function fakeIo(files) {
  const store = new Map(Object.entries(files));
  return {
    store,
    cwd: () => '/w',
    isFile: (path) => store.has(path.replace(/^\/w\//, '')),
    read: (path) => store.get(path.replace(/^\/w\//, '')),
    write: (path, text) => store.set(path.replace(/^\/w\//, ''), text),
    mkdir: () => {},
    list: (dir) => [...store.keys()]
      .filter((p) => (dir === '.' ? !p.includes('/') : p.startsWith(`${dir}/`)))
      .map((p) => (dir === '.' ? p : p.slice(dir.length + 1)))
      .filter((p) => !p.includes('/')).sort(),
    rename: (from, to) => { store.set(to, store.get(from)); store.delete(from); },
    copy: (from, to) => store.set(to, store.get(from)),
    sha256: (path) => digest(store.get(path.replace(/^\/w\//, ''))),
  };
}

function archives(prefix, targets = Object.values(brew.MARKERS)) {
  return Object.fromEntries(targets.map((t) => [`${prefix}/tool-1.2.3-${t}.tar.gz`, `archive ${t}`]));
}

function formulaJob({ formula = FORMULA, jsons = [ARM, INTEL], built = true } = {}) {
  const files = { 'Formula/tool.rb': formula, ...archives('artifacts') };
  jsons.forEach((json, i) => {
    files[`bottles/${i}.bottle.json`] = JSON.stringify(json);
    if (built) for (const { to } of brew.bottleFiles(json)) files[`artifacts/${to}`] = 'bottle';
  });
  return fakeIo(files);
}

function block(text) {
  return text.split('  # BOTTLE-START\n')[1].split('  # BOTTLE-END')[0];
}

function refusal(fn, expected) {
  assert.throws(fn, (error) => {
    assert.match(error.message, expected);
    assert.doesNotMatch(error.message, /\n/);
    return true;
  });
}

test('the local tap points the mac urls at the built archives', () => {
  const io = fakeIo({ 'Formula/tool.rb': FORMULA,
    ...archives('dist', ['aarch64-apple-darwin', 'x86_64-apple-darwin']) });
  assert.equal(brew.pointAtArchives(ENV, io), '/t/local-formula.rb');
  const local = io.store.get('/t/local-formula.rb');
  for (const [marker, target] of [['mac-arm', 'aarch64-apple-darwin'], ['mac-x86', 'x86_64-apple-darwin']]) {
    assert.ok(local.includes(`      url "file:///w/dist/tool-1.2.3-${target}.tar.gz"\n`
      + `      sha256 "${digest(`archive ${target}`)}" # ${marker}\n`), marker);
  }
  assert.equal(local.split('/releases/download/v#{version}/').length - 1, 2, 'the linux urls stay');
  assert.match(local, /^ {2}version "1\.2\.3"$/m);
  assert.ok(local.includes('  # BOTTLE-START\n  # BOTTLE-END\n'));
});

for (const damage of ['deleted', 'blank line', 'comment']) {
  test(`a mac sha256 line without its url line directly above fails (${damage})`, () => {
    const lines = FORMULA.split('\n');
    const i = lines.findIndex((line) => line.endsWith('# mac-x86'));
    if (damage === 'deleted') lines.splice(i - 1, 1);
    else lines.splice(i, 0, damage === 'blank line' ? '' : '      # the Intel archive');
    const io = fakeIo({ 'Formula/tool.rb': lines.join('\n'),
      ...archives('dist', ['aarch64-apple-darwin', 'x86_64-apple-darwin']) });
    refusal(() => brew.pointAtArchives(ENV, io),
      /^no url line directly above the # mac-x86 sha256 line$/);
  });
}

test('a missing mac archive fails the local tap', () => {
  const io = fakeIo({ 'Formula/tool.rb': FORMULA, ...archives('dist', ['aarch64-apple-darwin']) });
  refusal(() => brew.pointAtArchives(ENV, io),
    /^\/w\/dist\/tool-1\.2\.3-x86_64-apple-darwin\.tar\.gz was not built$/);
});

test('a missing formula fails naming it', () => {
  refusal(() => brew.pointAtArchives(ENV, fakeIo({})), /^Formula\/tool\.rb does not exist$/);
});

test('the bottles get the names their json records', () => {
  const io = fakeIo({ 'arm.bottle.json': JSON.stringify(ARM), 'intel.bottle.json': JSON.stringify(INTEL),
    'tool--1.2.3.arm64_sonoma.bottle.tar.gz': 'a', 'tool--1.2.3.sequoia.bottle.tar.gz': 'b' });
  assert.deepEqual(brew.renameBottles(io),
    ['tool-1.2.3.arm64_sonoma.bottle.tar.gz', 'tool-1.2.3.sequoia.bottle.tar.gz']);
  assert.deepEqual(io.list('bottle'), ['arm.bottle.json', 'intel.bottle.json',
    'tool-1.2.3.arm64_sonoma.bottle.tar.gz', 'tool-1.2.3.sequoia.bottle.tar.gz']);
});

test('no bottle json fails the rename', () => {
  refusal(() => brew.renameBottles(fakeIo({})), /^brew bottle wrote no json$/);
});

test('two bottles give the version, the four checksums and both bottles', () => {
  const io = formulaJob();
  const text = brew.rewriteFormula(ENV, io);
  assert.match(text, /^ {2}version "1\.2\.3"$/m);
  for (const [marker, target] of Object.entries(brew.MARKERS)) {
    assert.ok(text.includes(`sha256 "${digest(`archive ${target}`)}" # ${marker}\n`), marker);
  }
  assert.equal(block(text), [
    '  bottle do',
    '    root_url "https://github.com/owner/tool/releases/download/v1.2.3"',
    `    sha256 cellar: :any_skip_relocation, arm64_sonoma: "${'a'.repeat(64)}"`,
    `    sha256 cellar: :any_skip_relocation, sequoia: "${'b'.repeat(64)}"`,
    '  end', ''].join('\n'));
  assert.equal(io.store.get('Formula/tool.rb'), text);
  assert.equal(io.store.get('release-files/Formula/tool.rb'), text);
});

test('the cellar of a tag wins, and a Cellar path is quoted', () => {
  const lines = brew.bottleBlock([bottleJson('sonoma', 'c'.repeat(64), '/opt/homebrew/Cellar')],
    { repository: 'owner/tool', version: '1.2.3' });
  assert.equal(lines[2], `    sha256 cellar: "/opt/homebrew/Cellar", sonoma: "${'c'.repeat(64)}"`);
});

test('a bottle json without a cellar fails naming the tag', () => {
  const json = bottleJson('sonoma', 'c'.repeat(64));
  delete json['local/tool/tool'].bottle.cellar;
  refusal(() => brew.bottleBlock([json], { repository: 'owner/tool', version: '1.2.3' }),
    /^the bottle json of sonoma names no cellar$/);
});

test('the optional bottle missing still publishes the other', () => {
  const text = brew.rewriteFormula(ENV, formulaJob({ jsons: [ARM] }));
  assert.equal(block(text).split('sha256 cellar:').length - 1, 1);
});

test('zero bottles fail', () => {
  refusal(() => brew.rewriteFormula(ENV, formulaJob({ jsons: [] })), /^no bottles were built$/);
});

test('a bottle missing under its recorded name fails', () => {
  refusal(() => brew.rewriteFormula(ENV, formulaJob({ built: false })),
    /^bottle tool-1\.2\.3\.arm64_sonoma\.bottle\.tar\.gz was not built under that name$/);
});

test('a missing archive fails the formula job', () => {
  const io = formulaJob();
  io.store.delete('artifacts/tool-1.2.3-aarch64-unknown-linux-musl.tar.gz');
  refusal(() => brew.rewriteFormula(ENV, io),
    /^artifacts\/tool-1\.2\.3-aarch64-unknown-linux-musl\.tar\.gz was not built$/);
});

for (const marker of ['mac-arm', 'mac-x86', 'linux-x86', 'linux-arm', 'BOTTLE-START', 'BOTTLE-END']) {
  test(`a missing marker # ${marker} fails`, () => {
    const io = formulaJob({ formula: FORMULA.replace(` # ${marker}`, '') });
    refusal(() => brew.rewriteFormula(ENV, io),
      new RegExp(`^the marker # ${marker} is gone from Formula/tool\\.rb$`));
  });
}

test('a formula without a version line fails', () => {
  const io = formulaJob({ formula: FORMULA.replace('  version "0.0.0"\n', '') });
  refusal(() => brew.rewriteFormula(ENV, io), /^Formula\/tool\.rb has no version line$/);
});

test('a second run changes nothing', () => {
  const io = formulaJob();
  const first = brew.rewriteFormula(ENV, io);
  assert.equal(brew.rewriteFormula(ENV, io), first);
});

test('the previous release block is replaced whole', () => {
  const old = '  # BOTTLE-START\n  bottle do\n'
    + '    root_url "https://github.com/owner/tool/releases/download/v9.9.9"\n'
    + `    sha256 cellar: :any_skip_relocation, old_tag: "${'1'.repeat(64)}"\n`
    + '  end\n  # BOTTLE-END';
  const formula = FORMULA.replace('  # BOTTLE-START\n  # BOTTLE-END', old);
  const inside = block(brew.rewriteFormula(ENV, formulaJob({ formula })));
  assert.doesNotMatch(inside, /v9\.9\.9|old_tag/);
  assert.match(inside, /root_url "https:\/\/github\.com\/owner\/tool\/releases\/download\/v1\.2\.3"/);
});
