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
  assertPublicationRef,
  assertReviewedEnvironment,
  loadReviewedPrivateTarget,
  verifyPrivateArtifactRelease
} from './private-artifact-release.mjs';
import {
  privateContentSecurityPolicy,
  verifyPrivateArtifactCsp,
  writePrivateArtifactManifest
} from './private-artifact.mjs';

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
  writeFileSync(join(directory, 'index.html'), [
    '<!doctype html><html><head>',
    `<meta http-equiv="Content-Security-Policy" content="${privateContentSecurityPolicy(target.endpoint)}">`,
    '</head><body></body></html>'
  ].join(''));
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
      environment: publicationEnvironment(commit)
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

  it('accepts only an explicitly reviewed release ref', () => {
    const commit = '1'.repeat(40);
    const ref = 'refs/tags/release/v1.0.0';

    expect(assertPublicationRef(ref, commit, [{ref, commit}])).toEqual({ref, commit});
    expect(() => assertPublicationRef(ref, commit, [])).toThrow(/not explicitly reviewed/i);
    expect(() => assertPublicationRef('refs/heads/unreviewed', commit, [])).toThrow(/master.*reviewed release ref/i);
  });

  it('rejects an unreviewed ref before it can verify or publish an artifact', () => {
    const directory = temporaryArtifact();
    const commit = currentCommit();

    expect(() => verifyPrivateArtifactRelease({
      directory,
      expectedCommit: commit,
      environment: publicationEnvironment(commit, 'refs/heads/unreviewed'),
      reviewedReleaseRefs: []
    })).toThrow(/publication ref/i);
  });

  it.each([
    ['an HTML comment', '<head><!-- CSP_MARKER --></head><body></body>'],
    ['the document body', '<head></head><body>CSP_MARKER</body>']
  ])('rejects a CSP marker in %s instead of a real head meta element', (_name, document) => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-csp-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://private.example.test:2443/apiws';
    const marker = `<meta http-equiv="Content-Security-Policy" content="${privateContentSecurityPolicy(endpoint)}">`;
    writeFileSync(join(directory, 'index.html'), document.replace('CSP_MARKER', marker));

    expect(() => verifyPrivateArtifactCsp(directory, endpoint))
    .toThrow(/CSP does not match/i);
  });

  it('rejects a changed artifact byte and a stale source commit', () => {
    const directory = temporaryArtifact();
    const commit = currentCommit();
    const manifestPath = join(directory, 'mtproto-target.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));

    writeFileSync(join(directory, 'client.js'), readFileSync(join(directory, 'client.js'), 'utf8') + '\n// changed');
    expect(() => verifyPrivateArtifactRelease({
      directory,
      expectedCommit: commit,
      environment: publicationEnvironment(commit)
    }))
    .toThrow(/digest/i);

    writeFileSync(join(directory, 'client.js'), [
      `const endpoint = ${JSON.stringify(environment.MTPROTO_PRIVATE_ENDPOINT)};`,
      `const fingerprint = ${JSON.stringify(manifest.fingerprint)};`
    ].join('\n'));
    manifest.sourceCommit = '0'.repeat(40);
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
    expect(() => verifyPrivateArtifactRelease({
      directory,
      expectedCommit: commit,
      environment: publicationEnvironment(commit)
    }))
    .toThrow(/source commit/i);
  });
});

function publicationEnvironment(commit, ref = 'refs/heads/master') {
  return {
    ...environment,
    PRIVATE_ARTIFACT_COMMIT: commit,
    PRIVATE_ARTIFACT_REF: ref
  };
}

function currentCommit() {
  return execFileSync('git', ['rev-parse', '--verify', 'HEAD'], {
    cwd: repositoryRoot,
    encoding: 'utf8'
  }).trim();
}
