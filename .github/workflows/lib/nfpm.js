// repo-infra: workflow-lib v9
'use strict';

// ri-release-nfpm (D32): .deb and .rpm packages built by nfpm from the
// unpacked release archives, each read back before the release pull request
// opens. The step in ri-release-nfpm.yml hands `run` its environment and
// nothing else, so every input check and every refusal is a line in
// nfpm.test.js. The file system and the commands go through `io`, which the
// tests replace.

const { parsePackageFile } = require('./gitea.js');

// The variables the piece sets for every nfpm run. A packagers key that
// names one of them fails, so a config cannot shadow VERSION or ARCH.
const OWN = ['VERSION', 'SOURCE_DATE_EPOCH', 'MTIME', 'PACKAGER', 'TARGET', 'STAGE', 'ARCH'];
// nfpm translates amd64 and arm64 into x86_64 and aarch64 for rpm.
const ARCH = {
  'x86_64-unknown-linux-musl': 'amd64',
  'aarch64-unknown-linux-musl': 'arm64',
};
const NAME = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parsePackagers(text) {
  let packagers;
  try {
    packagers = JSON.parse(text);
  } catch (error) {
    throw new Error(`packagers is not JSON: ${error.message.replace(/\s+/g, ' ')}`);
  }
  const valid = isObject(packagers) && Object.keys(packagers).length > 0
    && Object.values(packagers).every((extra) => isObject(extra)
      && Object.values(extra).every((value) => typeof value === 'string'));
  if (!valid) {
    throw new Error('packagers must be a JSON object such as '
      + '{"deb": {}, "rpm": {"NAME": "value"}}: one key per packager, '
      + 'each mapping variable names to strings');
  }
  const unknown = Object.keys(packagers).filter((p) => p !== 'deb' && p !== 'rpm').sort();
  if (unknown.length > 0) {
    throw new Error(`packagers names ${unknown.join(', ')}; ri-release-nfpm builds deb and rpm`);
  }
  for (const [packager, extra] of Object.entries(packagers)) {
    const shadowed = Object.keys(extra).filter((key) => OWN.includes(key)).sort();
    if (shadowed.length > 0) {
      throw new Error(`packagers.${packager} sets ${shadowed.join(', ')}, `
        + 'which ri-release-nfpm sets itself');
    }
  }
  return packagers;
}

function parseTargets(text) {
  const targets = (text || '').split(/\s+/).filter(Boolean);
  if (targets.length === 0) throw new Error('archives names no target');
  for (const target of targets) {
    if (!Object.hasOwn(ARCH, target)) {
      throw new Error(`no package architecture is known for ${target}; archives takes `
        + Object.keys(ARCH).join(' and '));
    }
  }
  return targets;
}

// nfpm expands only top-level scalars, not the src: and dst: paths under
// contents:, so every ${NAME} in the file is replaced here, comments
// included. A name nobody sets stops the build instead of reaching nfpm as
// an empty string.
function expand(template, values, config) {
  const unset = [...new Set([...template.matchAll(NAME)].map((m) => m[1]))]
    .filter((name) => !Object.hasOwn(values, name)).sort();
  if (unset.length > 0) {
    throw new Error(`${config} uses ${unset.map((name) => `\${${name}}`).join(', ')}, `
      + 'which neither ri-release-nfpm nor packagers sets');
  }
  return template.replace(NAME, (_, name) => values[name]);
}

// nfpm 2.47.0 ignores SOURCE_DATE_EPOCH, so MTIME carries the same instant
// for the config's mtime: field.
function rfc3339(epoch) {
  return new Date(Number(epoch) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function variables({ version, epoch, packager, target, stage, extra }) {
  return {
    VERSION: version, SOURCE_DATE_EPOCH: epoch, MTIME: rfc3339(epoch), PACKAGER: packager,
    TARGET: target, STAGE: stage, ARCH: ARCH[target], ...extra,
  };
}

// The names ri-publish-gitea uploads; parsePackageFile in gitea.js is the
// one place they are written down.
function checkName(packager, file) {
  const parsed = parsePackageFile(file);
  if (packager === 'deb' && (!parsed || parsed.kind !== 'debian')) {
    throw new Error(`${file} is not name_version_arch.deb, the name ri-publish-gitea uploads`);
  }
  if (packager === 'rpm' && (!parsed || parsed.kind !== 'rpm')) {
    throw new Error(`${file} is not name-version-release.arch.rpm, `
      + 'the name ri-publish-gitea uploads');
  }
}

function readBack(packager, path, exec) {
  if (packager === 'deb') {
    return {
      version: exec('dpkg-deb', ['--field', path, 'Version']).trim(),
      files: exec('dpkg-deb', ['--contents', path]).split('\n')
        .filter((line) => line && !line.startsWith('d')),
    };
  }
  return {
    version: exec('rpm', ['-qp', '--queryformat', '%{VERSION}', path]).trim(),
    files: exec('rpm', ['-qlp', path]).split('\n').filter((line) => line.startsWith('/')),
  };
}

function nodeIo() {
  const fs = require('fs');
  const { execFileSync } = require('child_process');
  const stat = (path) => (fs.existsSync(path) ? fs.statSync(path) : null);
  return {
    isFile: (path) => Boolean(stat(path) && stat(path).isFile()),
    isDir: (path) => Boolean(stat(path) && stat(path).isDirectory()),
    read: (path) => fs.readFileSync(path, 'utf8'),
    write: (path, text) => fs.writeFileSync(path, text),
    mkdir: (path) => fs.mkdirSync(path, { recursive: true }),
    list: (path) => (fs.existsSync(path) ? fs.readdirSync(path).sort() : []),
    exec: (command, args, options = {}) => execFileSync(command, args, {
      encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], ...options,
    }),
  };
}

// Builds every package and returns one line per package for the log. Run
// in the checkout: archives/release-asset-<target>/ holds what
// download-artifact fetched, and packages/ receives the packages.
function run(env, io = nodeIo()) {
  const version = env.VERSION;
  const config = env.CONFIG;
  const temp = env.RUNNER_TEMP;
  const packagers = parsePackagers(env.PACKAGERS);
  const targets = parseTargets(env.ARCHIVES);
  if (!io.isFile(config)) throw new Error(`${config} does not exist`);
  const template = io.read(config);
  const epoch = io.exec('git', ['log', '-1', '--format=%ct', 'HEAD']).trim();
  io.mkdir('packages');
  const lines = [];
  for (const target of targets) {
    const folder = `archives/release-asset-${target}`;
    const found = io.list(folder).filter((name) => name.endsWith('.tar.gz'));
    if (found.length !== 1) {
      throw new Error(`release-asset-${target} holds ${found.length} .tar.gz files; `
        + 'one is expected');
    }
    const unpacked = `${temp}/stage/${target}`;
    io.mkdir(unpacked);
    io.exec('tar', ['-xzf', `${folder}/${found[0]}`, '-C', unpacked, '--no-same-owner']);
    const tops = io.list(unpacked);
    if (tops.length !== 1 || !io.isDir(`${unpacked}/${tops[0]}`)) {
      throw new Error(`${found[0]} must hold one folder, the <bin>/ of the archive layout`);
    }
    for (const [packager, extra] of Object.entries(packagers)) {
      const values = variables({
        version, epoch, packager, target, stage: `${unpacked}/${tops[0]}`, extra,
      });
      const expanded = `${temp}/nfpm-${target}-${packager}.yaml`;
      io.write(expanded, expand(template, values, config));
      const before = new Set(io.list('packages'));
      // The config is filled in already. nfpm gets the piece's own variables
      // and not the packagers values: {"deb": {"PATH": "x"}} would otherwise
      // replace the PATH nfpm is found on.
      const own = Object.fromEntries(OWN.map((name) => [name, values[name]]));
      io.exec('nfpm', ['package', '--config', expanded, '--packager', packager,
        '--target', 'packages'], { env: { ...env, ...own }, stdio: 'inherit' });
      const made = io.list('packages').filter((name) => !before.has(name));
      if (made.length !== 1) {
        throw new Error(`nfpm wrote ${made.length} files for ${target} ${packager}; `
          + 'one is expected');
      }
      const file = made[0];
      checkName(packager, file);
      const back = readBack(packager, `packages/${file}`, io.exec);
      if (back.version !== version && !back.version.startsWith(`${version}-`)) {
        throw new Error(`${file} carries version ${back.version}, not ${version}`);
      }
      if (back.files.length === 0) throw new Error(`${file} holds no files`);
      lines.push(`${file}: version ${back.version}, ${back.files.length} files`);
    }
  }
  return lines;
}

module.exports = { parsePackagers, parseTargets, expand, rfc3339, checkName, run };
