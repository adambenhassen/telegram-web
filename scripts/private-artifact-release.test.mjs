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
  REQUEST_WORKFLOW_NAME,
  assertPublicationRef,
  assertReviewedEnvironment,
  assertTrustedWorkflowRun,
  loadPublicationRequest,
  loadReviewedPrivateTarget,
  snapshotReviewedPrivateTarget,
  verifyPrivateArtifactRelease
} from './private-artifact-release.mjs';
import {verifyPublishedArtifact} from './private-artifact-publish-verify.mjs';
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

function temporaryArtifact(indexDocument) {
  const directory = mkdtempSync(join(tmpdir(), 'private-artifact-release-'));
  temporaryDirectories.push(directory);
  const {target} = loadReviewedPrivateTarget();
  writeFileSync(join(directory, 'index.html'), indexDocument || [
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

  it('rejects a request from a tampered workflow definition before target resolution', () => {
    expect(() => assertTrustedWorkflowRun({
      eventName: 'workflow_run',
      workflowName: 'Private MTProto Artifact Request',
      headBranch: 'feature/unreviewed',
      conclusion: 'success'
    })).toThrow(/master branch/i);
    expect(() => assertTrustedWorkflowRun({
      eventName: 'workflow_run',
      workflowName: 'Untrusted Request',
      headBranch: 'master',
      conclusion: 'success'
    })).toThrow(/not trusted/i);

    const publisherWorkflow = readFileSync(
      join(repositoryRoot, '.github/workflows/private-artifact.yml'),
      'utf8'
    );
    const requestWorkflow = readFileSync(
      join(repositoryRoot, '.github/workflows/private-artifact-request.yml'),
      'utf8'
    );
    expect(publisherWorkflow).toContain('workflow_run:');
    expect(publisherWorkflow).not.toContain('workflow_dispatch:');
    expect(publisherWorkflow).toContain('github.event.workflow_run.head_branch');
    expect(requestWorkflow).toContain('workflow_dispatch:');
    expect(requestWorkflow).toContain('target_ref:');
    expect(requestWorkflow).not.toContain('pnpm install');
  });

  it('accepts only an exact data-only publication request', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-request-'));
    temporaryDirectories.push(directory);
    const requestPath = join(directory, 'request.json');
    writeFileSync(requestPath, JSON.stringify({targetRef: 'refs/heads/master'}));
    expect(loadPublicationRequest(requestPath)).toEqual({targetRef: 'refs/heads/master'});
    writeFileSync(requestPath, JSON.stringify({targetRef: 'refs/heads/master', workflow: 'tampered'}));
    expect(() => loadPublicationRequest(requestPath)).toThrow(/fields/i);
  });

  it('loads a data-only request when workflow_run passes an empty target ref', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-prepare-'));
    temporaryDirectories.push(directory);
    const requestPath = join(directory, 'request.json');
    const outputDirectory = join(directory, 'snapshot');
    const outputPath = join(directory, 'github-output');
    const commit = currentCommit();
    writeFileSync(requestPath, JSON.stringify({targetRef: 'refs/heads/master'}));

    execFileSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'prepare',
      '--event', 'workflow_run',
      '--head-branch', 'master',
      '--conclusion', 'success',
      '--workflow-name', REQUEST_WORKFLOW_NAME,
      '--request', requestPath,
      '--target-ref', '',
      '--workflow-commit', commit,
      '--output', outputDirectory
    ], {
      cwd: repositoryRoot,
      env: {...process.env, GITHUB_OUTPUT: outputPath},
      encoding: 'utf8'
    });

    expect(JSON.parse(readFileSync(join(outputDirectory, 'snapshot.json'), 'utf8'))).toMatchObject({
      sourceRef: 'refs/heads/master',
      sourceCommit: commit
    });
    expect(readFileSync(outputPath, 'utf8')).toContain('source_ref=refs/heads/master');
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

  it.each([
    ['an HTML comment', '<!doctype html><html><head><!-- CSP_MARKER --></head><body></body></html>'],
    ['the document body', '<!doctype html><html><head></head><body>CSP_MARKER</body></html>']
  ])('publisher rejects a CSP marker in %s instead of a real head meta element', (_name, document) => {
    const {target} = loadReviewedPrivateTarget();
    const marker = `<meta http-equiv="Content-Security-Policy" content="${privateContentSecurityPolicy(target.endpoint)}">`;
    const directory = temporaryArtifact(document.replace('CSP_MARKER', marker));
    const commit = currentCommit();
    const snapshotDirectory = mkdtempSync(join(tmpdir(), 'private-artifact-publisher-csp-'));
    temporaryDirectories.push(snapshotDirectory);
    snapshotReviewedPrivateTarget({
      rootDirectory: repositoryRoot,
      sourceRef: 'refs/heads/master',
      sourceCommit: commit,
      reviewedWorkflowCommit: commit,
      outputDirectory: snapshotDirectory
    });
    const manifest = JSON.parse(readFileSync(join(directory, 'mtproto-target.json'), 'utf8'));

    expect(() => verifyPublishedArtifact({
      directory,
      snapshotDirectory,
      sourceRef: 'refs/heads/master',
      sourceCommit: commit,
      artifactDigest: manifest.artifactDigest.slice('sha256:'.length)
    })).toThrow(/CSP does not match/i);
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
  it('uses the immutable target snapshot and explicit publication inputs', () => {
    const directory = temporaryArtifact();
    const commit = currentCommit();
    const snapshotDirectory = mkdtempSync(join(tmpdir(), 'private-artifact-snapshot-'));
    temporaryDirectories.push(snapshotDirectory);
    const snapshot = snapshotReviewedPrivateTarget({
      rootDirectory: repositoryRoot,
      sourceRef: 'refs/heads/master',
      sourceCommit: commit,
      reviewedWorkflowCommit: commit,
      outputDirectory: snapshotDirectory
    });

    const result = verifyPrivateArtifactRelease({
      directory,
      expectedCommit: commit,
      publicationRef: 'refs/heads/master',
      targetRootDirectory: snapshotDirectory,
      reviewedReleaseRefs: snapshot.reviewedReleaseRefs,
      environment: {
        ...environment,
        MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: snapshot.keyPath,
        PRIVATE_ARTIFACT_REF: 'refs/heads/unreviewed',
        PRIVATE_ARTIFACT_COMMIT: '0'.repeat(40)
      }
    });
    expect(result.commit).toBe(commit);

    writeFileSync(snapshot.keyPath, 'tampered snapshot key');
    expect(() => verifyPrivateArtifactRelease({
      directory,
      expectedCommit: commit,
      publicationRef: 'refs/heads/master',
      targetRootDirectory: snapshotDirectory,
      reviewedReleaseRefs: snapshot.reviewedReleaseRefs,
      environment: {
        ...environment,
        MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: snapshot.keyPath
      }
    })).toThrow(/public-key file digest/i);
  });

  it('reverifies a downloaded artifact against the immutable snapshot', () => {
    const directory = temporaryArtifact();
    const commit = currentCommit();
    const snapshotDirectory = mkdtempSync(join(tmpdir(), 'private-artifact-publisher-'));
    temporaryDirectories.push(snapshotDirectory);
    snapshotReviewedPrivateTarget({
      rootDirectory: repositoryRoot,
      sourceRef: 'refs/heads/master',
      sourceCommit: commit,
      reviewedWorkflowCommit: commit,
      outputDirectory: snapshotDirectory
    });
    const manifest = JSON.parse(readFileSync(join(directory, 'mtproto-target.json'), 'utf8'));

    expect(verifyPublishedArtifact({
      directory,
      snapshotDirectory,
      sourceRef: 'refs/heads/master',
      sourceCommit: commit,
      artifactDigest: manifest.artifactDigest.slice('sha256:'.length)
    }).sourceCommit).toBe(commit);

    writeFileSync(join(directory, 'client.js'), readFileSync(join(directory, 'client.js'), 'utf8') + '\n// mutated');
    expect(() => verifyPublishedArtifact({
      directory,
      snapshotDirectory,
      sourceRef: 'refs/heads/master',
      sourceCommit: commit,
      artifactDigest: manifest.artifactDigest.slice('sha256:'.length)
    })).toThrow(/digest/i);
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
