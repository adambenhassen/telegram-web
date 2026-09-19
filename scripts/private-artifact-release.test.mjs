import {execFileSync} from 'node:child_process';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {afterAll, describe, expect, it} from 'vitest';
import {
  assertReviewedEnvironment,
  loadReviewedPrivateTarget,
  verifyPrivateArtifactRelease
} from './private-artifact-release.mjs';
import {privateContentSecurityPolicy, writePrivateArtifactManifest} from './private-artifact.mjs';

const temporaryDirectories = [];
const repositoryRoot = resolve('.');
const environment = {
  MTPROTO_TARGET_MODE: 'private',
  MTPROTO_PRIVATE_ENDPOINT: 'wss://private.example.test:2443/apiws',
  MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: 'scripts/fixtures/private-mtproto-public.pem'
};

afterAll(() => {
  for(const directory of temporaryDirectories) {
    rmSync(directory, {recursive: true, force: true});
  }
});

function temporaryArtifact() {
  const directory = mkdtempSync(join(tmpdir(), 'private-artifact-release-'));
  temporaryDirectories.push(directory);
  const {target} = loadReviewedPrivateTarget();
  writeFileSync(join(directory, 'index.html'), `<meta http-equiv="Content-Security-Policy" content="${privateContentSecurityPolicy(target.endpoint)}">`);
  writeFileSync(join(directory, 'client.js'), [
    `const endpoint = ${JSON.stringify(target.endpoint)};`,
    `const fingerprint = ${JSON.stringify(target.fingerprint)};`
  ].join('\n'));
  writePrivateArtifactManifest(directory, target, repositoryRoot);
  return directory;
}

describe('private artifact publication attestation', () => {
  it('loads the reviewed target and verifies a complete release unit', () => {
    const directory = temporaryArtifact();
    const commit = currentCommit();
    const result = verifyPrivateArtifactRelease({
      directory,
      expectedCommit: commit,
      environment
    });

    expect(result.commit).toBe(commit);
    expect(result.manifest.sourceCommit).toBe(commit);
    expect(result.manifest.artifactDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('rejects an endpoint override before artifact verification', () => {
    expect(() => assertReviewedEnvironment({
      MTPROTO_TARGET_MODE: 'private',
      MTPROTO_PRIVATE_ENDPOINT: 'wss://private.example.test:2443/apiws',
      MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: 'scripts/fixtures/private-mtproto-public.pem'
    }, {
      ...environment,
      MTPROTO_PRIVATE_ENDPOINT: 'wss://other.example.test:2443/apiws'
    })).toThrow(/endpoint.*reviewed target/i);
  });

  it('rejects a changed artifact byte and a stale source commit', () => {
    const directory = temporaryArtifact();
    const commit = currentCommit();
    const manifestPath = join(directory, 'mtproto-target.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

    writeFileSync(join(directory, 'client.js'), readFileSync(join(directory, 'client.js'), 'utf8') + '\n// changed');
    expect(() => verifyPrivateArtifactRelease({directory, expectedCommit: commit, environment}))
    .toThrow(/digest/i);

    writeFileSync(join(directory, 'client.js'), [
      `const endpoint = ${JSON.stringify(environment.MTPROTO_PRIVATE_ENDPOINT)};`,
      `const fingerprint = ${JSON.stringify(manifest.fingerprint)};`
    ].join('\n'));
    manifest.sourceCommit = '0'.repeat(40);
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
    expect(() => verifyPrivateArtifactRelease({directory, expectedCommit: commit, environment}))
    .toThrow(/source commit/i);
  });
});

function currentCommit() {
  return execFileSync('git', ['rev-parse', '--verify', 'HEAD'], {
    cwd: repositoryRoot,
    encoding: 'utf8'
  }).trim();
}
