import {execFileSync, spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {afterAll, describe, expect, it} from 'vitest';
import * as privateArtifactRelease from './private-artifact-release.mjs';
import {
  REVIEWED_PRIVATE_TARGET,
  REQUEST_WORKFLOW_NAME,
  assertPublicationRef,
  assertReviewedEnvironment,
  assertTrustedWorkflowRun,
  loadPublicationRequest,
  loadReviewedPrivateTarget,
  snapshotReviewedPrivateTarget,
  verifyPrivateArtifactRelease
} from './private-artifact-release.mjs';
import {resolveMtprotoTarget} from './mtproto-target.mjs';
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
    expect(() => assertTrustedWorkflowRun({
      eventName: 'workflow_run',
      workflowName: '',
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
    expect(requestWorkflow).toContain('repository_dispatch:');
    expect(requestWorkflow).not.toContain('workflow_dispatch:');
    expect(requestWorkflow).toContain('github.event.client_payload.target_ref');
    expect(requestWorkflow).toContain("github.ref == 'refs/heads/master'");
    expect(requestWorkflow).toContain('permissions: {}');
    expect(requestWorkflow).not.toContain('actions: write');
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

  it('skips publication on a master push when the reviewed target is unchanged', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-push-'));
    temporaryDirectories.push(directory);
    const outputDirectory = join(directory, 'snapshot');
    const outputPath = join(directory, 'github-output');
    const commit = currentCommit();

    execFileSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'prepare',
      '--event', 'push',
      '--head-branch', 'master',
      '--conclusion', 'success',
      '--workflow-name', '',
      '--request', join(directory, 'request.json'),
      '--target-ref', 'refs/heads/master',
      '--workflow-commit', commit,
      '--previous-commit', commit,
      '--output', outputDirectory
    ], {
      cwd: repositoryRoot,
      env: {...process.env, GITHUB_OUTPUT: outputPath},
      encoding: 'utf8'
    });

    expect(readFileSync(outputPath, 'utf8')).toContain('publish_private_artifact=false');
    expect(existsSync(join(outputDirectory, 'snapshot.json'))).toBe(false);
    const publisherWorkflow = readFileSync(join(repositoryRoot, '.github/workflows/private-artifact.yml'), 'utf8');
    expect(publisherWorkflow).toContain("needs.publication-prepare.outputs.publish_private_artifact == 'true'");
    expect(publisherWorkflow).toContain("steps.prepare.outputs.publish_private_artifact == 'true'");
  });

  it('prepares publication when a master push changes the reviewed target', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-push-target-change-'));
    temporaryDirectories.push(directory);
    const outputDirectory = join(directory, 'snapshot');
    const outputPath = join(directory, 'github-output');
    const commit = currentCommit();
    // Supply the prior target tree directly so this case does not depend on local commit history.
    const {tree: previousCommit, objectDirectory, alternateObjectDirectory} = previousTargetTree(directory);

    execFileSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'prepare',
      '--event', 'push',
      '--head-branch', 'master',
      '--conclusion', 'success',
      '--workflow-name', '',
      '--request', join(directory, 'request.json'),
      '--target-ref', 'refs/heads/master',
      '--workflow-commit', commit,
      '--previous-commit', previousCommit,
      '--output', outputDirectory
    ], {
      cwd: repositoryRoot,
      env: {
        ...process.env,
        GITHUB_OUTPUT: outputPath,
        GIT_OBJECT_DIRECTORY: objectDirectory,
        GIT_ALTERNATE_OBJECT_DIRECTORIES: alternateObjectDirectory
      },
      encoding: 'utf8'
    });

    expect(readFileSync(outputPath, 'utf8')).toContain('publish_private_artifact=true');
    expect(JSON.parse(readFileSync(join(outputDirectory, 'snapshot.json'), 'utf8'))).toMatchObject({
      sourceRef: 'refs/heads/master',
      sourceCommit: commit
    });
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
    ['the document body', '<head></head><body>CSP_MARKER</body>'],
    ['a fake head after the body', '<!doctype html><html><body><head>CSP_MARKER</head></body></html>'],
    ['non-whitespace text before the head', '<!doctype html><html>text<head>CSP_MARKER</head><body></body></html>'],
    ['non-whitespace text in the head', '<!doctype html><html><head>textCSP_MARKER</head><body></body></html>'],
    ['NBSP before the document', '\u00a0<!doctype html><html><head>CSP_MARKER</head><body></body></html>'],
    ['EM SPACE before the document', '\u2003<!doctype html><html><head>CSP_MARKER</head><body></body></html>'],
    ['BOM before the document', '\ufeff<!doctype html><html><head>CSP_MARKER</head><body></body></html>'],
    ['a title raw-text element', '<!doctype html><html><head><title>CSP_MARKER</title></head><body></body></html>'],
    ['a textarea raw-text element', '<!doctype html><html><head><textarea>CSP_MARKER</textarea></head><body></body></html>'],
    ['a template element', '<!doctype html><html><head><template>CSP_MARKER</template></head><body></body></html>'],
    ['an SVG foreign-content element', '<!doctype html><html><head><svg>CSP_MARKER</svg></head><body></body></html>']
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
    ['an NBSP after the tag opener', '<!doctype html><html><head><\u00a0meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['an NBSP between attributes', '<!doctype html><html><head><meta http-equiv="Content-Security-Policy"\u00a0content="CSP_POLICY"></head><body></body></html>']
  ])('rejects a CSP parsed through %s instead of by the browser', (_name, document) => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-csp-lexing-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://private.example.test:2443/apiws';
    writeFileSync(join(directory, 'index.html'), document.replace(
      'CSP_POLICY',
      privateContentSecurityPolicy(endpoint)
    ));

    expect(() => verifyPrivateArtifactCsp(directory, endpoint))
    .toThrow(/CSP does not match/i);
  });

  it.each([
    ['a non-ASCII tag start before the head', '<!doctype html><html><\u00e9><head><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['a digit tag start in the head', '<!doctype html><html><head><9foo><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['a question-mark tag name in the head', '<!doctype html><html><head><meta?><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['an underscore tag name in the head', '<!doctype html><html><head><meta_bad><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['an equals-sign tag name in the head', '<!doctype html><html><head><meta=bad><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['a body end tag in the head', '<!doctype html><html><head></body><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head></html>'],
    ['an html end tag in the head', '<!doctype html><html><head></html><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head></html>'],
    ['a br end tag in the head', '<!doctype html><html><head></br><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head></html>']
  ])('rejects a CSP after %s because the malformed markup leaves head context', (_name, document) => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-csp-malformed-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://private.example.test:2443/apiws';
    writeFileSync(join(directory, 'index.html'), document.replace(
      'CSP_POLICY',
      privateContentSecurityPolicy(endpoint)
    ));

    expect(() => verifyPrivateArtifactCsp(directory, endpoint))
    .toThrow(/CSP does not match/i);
  });

  it.each([
    ['whitespace after the tag opener', '<!doctype html><html><head>< meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['whitespace after the closing slash', '<!doctype html><html><head>< /meta><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>']
  ])('rejects a CSP parsed through %s instead of by the browser', (_name, document) => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-csp-tag-start-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://private.example.test:2443/apiws';
    writeFileSync(join(directory, 'index.html'), document.replace(
      'CSP_POLICY',
      privateContentSecurityPolicy(endpoint)
    ));

    expect(() => verifyPrivateArtifactCsp(directory, endpoint))
    .toThrow(/CSP does not match/i);
  });

  it('rejects a CSP with padded http-equiv instead of by the browser', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-csp-http-equiv-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://private.example.test:2443/apiws';
    writeFileSync(join(directory, 'index.html'), [
      '<!doctype html><html><head>',
      '<meta http-equiv=" Content-Security-Policy " content="' +
      privateContentSecurityPolicy(endpoint) +
      '">',
      '</head><body></body></html>'
    ].join(''));

    expect(() => verifyPrivateArtifactCsp(directory, endpoint))
    .toThrow(/CSP does not match/i);
  });

  it('uses the first duplicate CSP attribute, matching browser parsing', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-csp-duplicate-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://private.example.test:2443/apiws';
    const otherPolicy = privateContentSecurityPolicy('wss://other.example.test:2443/apiws');
    const expectedPolicy = privateContentSecurityPolicy(endpoint);
    writeFileSync(join(directory, 'index.html'), [
      '<!doctype html><html><head>',
      `<meta http-equiv="Content-Security-Policy" content="${otherPolicy}" content="${expectedPolicy}">`,
      '</head><body></body></html>'
    ].join(''));

    expect(() => verifyPrivateArtifactCsp(directory, endpoint))
    .toThrow(/CSP does not match/i);
  });

  it.each([
    ['textarea', '<textarea></textarea>'],
    ['SVG', '<svg></svg>']
  ])('does not treat CSP after %s as document-head policy', (_name, container) => {
    const directory = mkdtempSync(join(tmpdir(), 'private-artifact-csp-context-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://private.example.test:2443/apiws';
    const policy = privateContentSecurityPolicy(endpoint);
    writeFileSync(join(directory, 'index.html'), [
      '<!doctype html><html><head>',
      container,
      `<meta http-equiv="Content-Security-Policy" content="${policy}">`,
      '</head><body></body></html>'
    ].join(''));

    expect(() => verifyPrivateArtifactCsp(directory, endpoint))
    .toThrow(/CSP does not match/i);
  });

  it.each([
    ['an HTML comment', '<!doctype html><html><head><!-- CSP_MARKER --></head><body></body></html>'],
    ['the document body', '<!doctype html><html><head></head><body>CSP_MARKER</body></html>'],
    ['non-whitespace text before the head', '<!doctype html><html>text<head>CSP_MARKER</head><body></body></html>'],
    ['non-whitespace text in the head', '<!doctype html><html><head>textCSP_MARKER</head><body></body></html>'],
    ['NBSP before the document', '\u00a0<!doctype html><html><head>CSP_MARKER</head><body></body></html>'],
    ['EM SPACE before the document', '\u2003<!doctype html><html><head>CSP_MARKER</head><body></body></html>'],
    ['BOM before the document', '\ufeff<!doctype html><html><head>CSP_MARKER</head><body></body></html>'],
    ['a title raw-text element', '<!doctype html><html><head><title>CSP_MARKER</title></head><body></body></html>'],
    ['a textarea raw-text element', '<!doctype html><html><head><textarea>CSP_MARKER</textarea></head><body></body></html>'],
    ['a template element', '<!doctype html><html><head><template>CSP_MARKER</template></head><body></body></html>'],
    ['an SVG foreign-content element', '<!doctype html><html><head><svg>CSP_MARKER</svg></head><body></body></html>']
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

  it.each([
    ['an NBSP after the tag opener', '<!doctype html><html><head><\u00a0meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['an NBSP between attributes', '<!doctype html><html><head><meta http-equiv="Content-Security-Policy"\u00a0content="CSP_POLICY"></head><body></body></html>']
  ])('publisher rejects a CSP parsed through %s instead of by the browser', (_name, document) => {
    const {target} = loadReviewedPrivateTarget();
    const directory = temporaryArtifact(document.replace(
      'CSP_POLICY',
      privateContentSecurityPolicy(target.endpoint)
    ));
    const commit = currentCommit();
    const snapshotDirectory = mkdtempSync(join(tmpdir(), 'private-artifact-publisher-csp-lexing-'));
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

  it.each([
    ['a non-ASCII tag start before the head', '<!doctype html><html><\u00e9><head><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['a digit tag start in the head', '<!doctype html><html><head><9foo><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['a question-mark tag name in the head', '<!doctype html><html><head><meta?><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['an underscore tag name in the head', '<!doctype html><html><head><meta_bad><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['an equals-sign tag name in the head', '<!doctype html><html><head><meta=bad><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['a body end tag in the head', '<!doctype html><html><head></body><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head></html>'],
    ['an html end tag in the head', '<!doctype html><html><head></html><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head></html>'],
    ['a br end tag in the head', '<!doctype html><html><head></br><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head></html>']
  ])('publisher rejects a CSP after %s because the malformed markup leaves head context', (_name, document) => {
    const {target} = loadReviewedPrivateTarget();
    const directory = temporaryArtifact(document.replace(
      'CSP_POLICY',
      privateContentSecurityPolicy(target.endpoint)
    ));
    const commit = currentCommit();
    const snapshotDirectory = mkdtempSync(join(tmpdir(), 'private-artifact-publisher-csp-malformed-'));
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

  it.each([
    ['whitespace after the tag opener', '<!doctype html><html><head>< meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>'],
    ['whitespace after the closing slash', '<!doctype html><html><head>< /meta><meta http-equiv="Content-Security-Policy" content="CSP_POLICY"></head><body></body></html>']
  ])('publisher rejects a CSP parsed through %s instead of by the browser', (_name, document) => {
    const {target} = loadReviewedPrivateTarget();
    const directory = temporaryArtifact(document.replace(
      'CSP_POLICY',
      privateContentSecurityPolicy(target.endpoint)
    ));
    const commit = currentCommit();
    const snapshotDirectory = mkdtempSync(join(tmpdir(), 'private-artifact-publisher-csp-tag-start-'));
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

  it('publisher rejects a CSP with padded http-equiv instead of by the browser', () => {
    const {target} = loadReviewedPrivateTarget();
    const directory = temporaryArtifact([
      '<!doctype html><html><head>',
      '<meta http-equiv=" Content-Security-Policy " content="' +
      privateContentSecurityPolicy(target.endpoint) +
      '">',
      '</head><body></body></html>'
    ].join(''));
    const commit = currentCommit();
    const snapshotDirectory = mkdtempSync(join(tmpdir(), 'private-artifact-publisher-csp-http-equiv-'));
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

  it('preserves the hidden version resource through the isolated publisher transfer', () => {
    const directory = temporaryArtifact();
    const versionResource = '.well-known/telegram-web/version.txt';
    const versionContents = '2.2 (676)\n';
    mkdirSync(join(directory, '.well-known/telegram-web'), {recursive: true});
    writeFileSync(join(directory, versionResource), versionContents);
    const {target} = loadReviewedPrivateTarget();
    const manifest = writePrivateArtifactManifest(directory, target, repositoryRoot);
    const commit = currentCommit();
    const transferDirectory = mkdtempSync(join(tmpdir(), 'private-artifact-transfer-'));
    temporaryDirectories.push(transferDirectory);
    const downloadedDirectory = join(transferDirectory, 'dist-private');
    const snapshotDirectory = mkdtempSync(join(tmpdir(), 'private-artifact-transfer-snapshot-'));
    temporaryDirectories.push(snapshotDirectory);
    snapshotReviewedPrivateTarget({
      rootDirectory: repositoryRoot,
      sourceRef: 'refs/heads/master',
      sourceCommit: commit,
      reviewedWorkflowCommit: commit,
      outputDirectory: snapshotDirectory
    });

    const publisherWorkflow = readFileSync(
      join(repositoryRoot, '.github/workflows/private-artifact.yml'),
      'utf8'
    );
    for(const name of [
      'Stage audited artifact for the isolated publisher',
      'Publish artifact and sidecar as one release unit'
    ]) {
      const start = publisherWorkflow.indexOf(`      - name: ${name}\n`);
      expect(start).toBeGreaterThanOrEqual(0);
      const nextStep = publisherWorkflow.indexOf('\n      - name: ', start + 1);
      const step = publisherWorkflow.slice(start, nextStep === -1 ? undefined : nextStep);
      expect(step).toContain('uses: actions/upload-artifact@');
      expect(step).toContain('          path: dist-private');
      expect(step).toContain('          include-hidden-files: true');
    }

    cpSync(directory, downloadedDirectory, {recursive: true});
    expect(readFileSync(join(downloadedDirectory, versionResource), 'utf8')).toBe(versionContents);
    expect(verifyPublishedArtifact({
      directory: downloadedDirectory,
      snapshotDirectory,
      sourceRef: 'refs/heads/master',
      sourceCommit: commit,
      artifactDigest: manifest.artifactDigest.slice('sha256:'.length)
    }).sourceCommit).toBe(commit);
  });
});

describe('private target diagnostics', () => {
  const provenance = {
    sourceCommit: 'a'.repeat(40),
    workflowCommit: 'b'.repeat(40),
    targetRef: 'refs/heads/master',
    requestSha256: 'c'.repeat(64),
    targetAttestationBlob: 'd'.repeat(40)
  };
  const runtime = {
    imageOS: 'ubuntu24',
    imageVersion: '20260927.320.1',
    node: 'v24.18.0',
    openssl: process.versions.openssl
  };
  const failureCodes = [
    'MODE_INVALID', 'FIELDS_MISSING', 'FIELD_UNRECOGNIZED',
    'ENDPOINT_PREFIX', 'ENDPOINT_PARSE', 'ENDPOINT_SCHEME', 'ENDPOINT_CREDENTIALS',
    'ENDPOINT_QUERY', 'ENDPOINT_FRAGMENT', 'ENDPOINT_EMPTY_HOST', 'ENDPOINT_TELEGRAM_ORG',
    'KEY_FILE_OPEN', 'KEY_FILE_SHAPE', 'KEY_FILE_READ', 'KEY_PRIVATE_MATERIAL',
    'KEY_PEM_SHAPE', 'KEY_BASE64_NONCANONICAL', 'KEY_PARSE', 'KEY_DER_NONCANONICAL',
    'KEY_JWK_MISSING', 'KEY_SIZE_EXPONENT', 'UNKNOWN'
  ];
  const linePatterns = [
    /^failureCode=(?:NONE|MODE_INVALID|FIELDS_MISSING|FIELD_UNRECOGNIZED|ENDPOINT_PREFIX|ENDPOINT_PARSE|ENDPOINT_SCHEME|ENDPOINT_CREDENTIALS|ENDPOINT_QUERY|ENDPOINT_FRAGMENT|ENDPOINT_EMPTY_HOST|ENDPOINT_TELEGRAM_ORG|KEY_FILE_OPEN|KEY_FILE_SHAPE|KEY_FILE_READ|KEY_PRIVATE_MATERIAL|KEY_PEM_SHAPE|KEY_BASE64_NONCANONICAL|KEY_PARSE|KEY_DER_NONCANONICAL|KEY_JWK_MISSING|KEY_SIZE_EXPONENT|UNKNOWN)$/,
    /^opensslErrorCode=(?:ERR_OSSL_[A-Z0-9_]{1,56}|other)$/,
    /^imageOS=(?:[a-z0-9]{1,32}|invalid)$/,
    /^imageVersion=(?:[0-9.]{1,32}|invalid)$/,
    /^node=(?:v\d+\.\d+\.\d+|invalid)$/,
    /^openssl=(?:\d+\.\d+\.\d+[a-z0-9.+-]{0,16}|invalid)$/,
    /^sourceCommit=(?:[0-9a-f]{40}|invalid)$/,
    /^workflowCommit=(?:[0-9a-f]{40}|invalid)$/,
    /^targetRef=(?:refs\/heads\/master|refs\/tags\/release(?:[/-])[A-Za-z0-9][A-Za-z0-9._/-]*|invalid)$/,
    /^requestSha256=(?:[0-9a-f]{64}|invalid)$/,
    /^targetAttestationBlob=(?:[0-9a-f]{40,64}|invalid)$/
  ];

  function formatDiagnostic(options) {
    expect(typeof privateArtifactRelease.formatTargetDiagnostic).toBe('function');
    return privateArtifactRelease.formatTargetDiagnostic(options);
  }

  it.each(failureCodes)('formats %s using only fixed allowlisted lines', (code) => {
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-canary-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://canary-target.example.test:2443/apiws?canary=query';
    const keyCanary = 'Q0FOREVZLUtFWS1NQVRFUklBTC0xMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=';
    const keyCanaries = keyCanary.match(/[A-Za-z0-9+/=]{16,}/g) || [];
    const keyPath = join(directory, 'canary-private-key.pem');
    writeFileSync(keyPath, keyCanary);
    const error = new Error(`Error: ${endpoint} ${keyPath} ${keyCanary}`);
    error.code = code;
    error.input = endpoint;
    error.cause = new Error(`cause ${keyCanary}`);

    const output = formatDiagnostic({error, provenance, runtime});
    const lines = output.split('\n');
    expect(lines).toEqual([
      `failureCode=${code}`,
      ...(code === 'KEY_PARSE' ? ['opensslErrorCode=other'] : []),
      `imageOS=${runtime.imageOS}`,
      `imageVersion=${runtime.imageVersion}`,
      `node=${runtime.node}`,
      `openssl=${runtime.openssl}`,
      `sourceCommit=${provenance.sourceCommit}`,
      `workflowCommit=${provenance.workflowCommit}`,
      `targetRef=${provenance.targetRef}`,
      `requestSha256=${provenance.requestSha256}`,
      `targetAttestationBlob=${provenance.targetAttestationBlob}`
    ]);
    for(const line of lines) {
      expect(linePatterns.some((pattern) => pattern.test(line))).toBe(true);
    }
    expect(output).not.toContain('canary-target.example.test');
    expect(output).not.toContain(endpoint);
    expect(output).not.toContain(keyPath);
    expect(output).not.toContain(keyCanary);
    for(const keyRun of keyCanaries) {
      expect(output).not.toContain(keyRun);
    }
    expect(output).not.toContain('cause');
    expect(output).not.toContain('Error:');
    expect(output).not.toContain('    at ');
  });

  it('redacts error.input from a real malformed endpoint validation', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-canary-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://canary-target.example.test:bad/apiws?canary=query';
    const keyCanary = 'Q0FOREVZLUtFWS1NQVRFUklBTC0xMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=';
    const keyPath = join(directory, 'canary-private-key.pem');
    writeFileSync(keyPath, keyCanary);
    let error;
    try {
      resolveMtprotoTarget({
        MTPROTO_TARGET_MODE: 'private',
        MTPROTO_PRIVATE_ENDPOINT: endpoint,
        MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath
      });
    } catch(cause) {
      error = cause;
    }
    error.input = endpoint;
    error.cause = new Error(`cause ${keyCanary}`);

    const output = formatDiagnostic({error, provenance, runtime});
    expect(error).toMatchObject({code: 'ENDPOINT_PARSE'});
    expect(output.split('\n')).toEqual([
      'failureCode=ENDPOINT_PARSE',
      `imageOS=${runtime.imageOS}`,
      `imageVersion=${runtime.imageVersion}`,
      `node=${runtime.node}`,
      `openssl=${runtime.openssl}`,
      `sourceCommit=${provenance.sourceCommit}`,
      `workflowCommit=${provenance.workflowCommit}`,
      `targetRef=${provenance.targetRef}`,
      `requestSha256=${provenance.requestSha256}`,
      `targetAttestationBlob=${provenance.targetAttestationBlob}`
    ]);
    expect(output).not.toContain('canary-target.example.test');
    expect(output).not.toContain(endpoint);
    expect(output).not.toContain(keyPath);
    expect(output).not.toContain(keyCanary);
    expect(output).not.toContain('cause');
    expect(output).not.toContain('Error:');
    expect(output).not.toContain('    at ');
  });

  it('sanitizes unsafe runtime values and validates the OpenSSL parse code', () => {
    const keyParseError = new Error('private parse detail', {
      cause: Object.assign(new Error('private OpenSSL detail'), {code: 'ERR_OSSL_CANARY'})
    });
    keyParseError.code = 'KEY_PARSE';
    const wrappedError = new Error('outer wrapper', {cause: keyParseError});
    const output = formatDiagnostic({
      error: wrappedError,
      provenance,
      runtime: {
        imageOS: 'Ubuntu-26.04\ncanary',
        imageVersion: '20260927.149.1\ncanary',
        node: 'node-canary',
        openssl: 'openssl-canary'
      }
    });

    expect(output.split('\n')).toEqual([
      'failureCode=KEY_PARSE',
      'opensslErrorCode=ERR_OSSL_CANARY',
      'imageOS=invalid',
      'imageVersion=invalid',
      'node=invalid',
      'openssl=invalid',
      `sourceCommit=${provenance.sourceCommit}`,
      `workflowCommit=${provenance.workflowCommit}`,
      `targetRef=${provenance.targetRef}`,
      `requestSha256=${provenance.requestSha256}`,
      `targetAttestationBlob=${provenance.targetAttestationBlob}`
    ]);
    expect(output).not.toContain('private');
    expect(output).not.toContain('canary');
  });

  it('sanitizes untrusted provenance values before emitting them', () => {
    const output = formatDiagnostic({
      error: new Error('canary exception'),
      provenance: {
        sourceCommit: 'canary-source',
        workflowCommit: 'canary-workflow',
        targetRef: 'refs/heads/master\ncanary-host',
        requestSha256: 'canary-request',
        targetAttestationBlob: 'canary-blob'
      },
      runtime
    });

    expect(output.split('\n')).toEqual([
      'failureCode=UNKNOWN',
      `imageOS=${runtime.imageOS}`,
      `imageVersion=${runtime.imageVersion}`,
      `node=${runtime.node}`,
      `openssl=${runtime.openssl}`,
      'sourceCommit=invalid',
      'workflowCommit=invalid',
      'targetRef=invalid',
      'requestSha256=invalid',
      'targetAttestationBlob=invalid'
    ]);
    for(const line of output.split('\n')) {
      expect(linePatterns.some((pattern) => pattern.test(line))).toBe(true);
    }
    expect(output).not.toContain('canary');
  });

  it('emits the reviewed attestation diagnosis and leaves GITHUB_OUTPUT empty', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-'));
    temporaryDirectories.push(directory);
    const requestPath = join(directory, 'request.json');
    const outputPath = join(directory, 'github-output');
    const requestContents = JSON.stringify({targetRef: 'refs/heads/master'});
    writeFileSync(requestPath, requestContents);
    writeFileSync(outputPath, '');
    const commit = currentCommit();
    const attestationBlob = execFileSync('git', ['rev-parse', '--verify', `${commit}:${REVIEWED_PRIVATE_TARGET}`], {
      cwd: repositoryRoot,
      encoding: 'utf8'
    }).trim();
    const result = spawnSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'diagnose-target',
      '--request', requestPath,
      '--workflow-commit', commit
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GITHUB_OUTPUT: outputPath,
        ImageOS: 'Ubuntu-26.04-canary',
        ImageVersion: '20260927.149.1\ncanary',
        PRIVATE_ARTIFACT_TARGET_REF: 'refs/tags/release/canary',
        MTPROTO_PRIVATE_ENDPOINT: 'wss://canary-target.example.test/apiws?canary=query',
        MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: '/canary-key/private.pem'
      }
    });
    const requestSha256 = createHash('sha256').update(requestContents).digest('hex');

    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toBe([
      'failureCode=NONE',
      'imageOS=invalid',
      'imageVersion=invalid',
      `node=${process.version}`,
      `openssl=${process.versions.openssl}`,
      `sourceCommit=${commit}`,
      `workflowCommit=${commit}`,
      'targetRef=refs/heads/master',
      `requestSha256=${requestSha256}`,
      `targetAttestationBlob=${attestationBlob}`
    ].join('\n') + '\n');
    expect(readFileSync(outputPath, 'utf8')).toBe('');
  });

  it('reports a malformed reviewed endpoint without emitting error.input', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-parse-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://canary-target.example.test:bad/apiws?canary=query';
    const keyCanary = 'Q0FOREVZLUtFWS1NQVRFUklBTC0xMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=';
    const requestPath = join(directory, 'request.json');
    const outputPath = join(directory, 'github-output');
    const requestContents = JSON.stringify({targetRef: 'refs/heads/master'});
    writeFileSync(requestPath, requestContents);
    writeFileSync(outputPath, '');
    const {tree, targetBlob, gitEnvironment} = privateTargetTreeWithOverrides(directory, endpoint, keyCanary);
    const result = spawnSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'diagnose-target',
      '--request', requestPath,
      '--workflow-commit', tree
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        ...gitEnvironment,
        GITHUB_OUTPUT: outputPath,
        ImageOS: 'ubuntu26',
        ImageVersion: '20260927.149.1'
      }
    });
    const requestSha256 = createHash('sha256').update(requestContents).digest('hex');

    expect(result.status).toBe(1);
    expect(result.stderr).toBe('');
    expect(result.stdout).toBe([
      'failureCode=ENDPOINT_PARSE',
      'imageOS=ubuntu26',
      'imageVersion=20260927.149.1',
      `node=${process.version}`,
      `openssl=${process.versions.openssl}`,
      `sourceCommit=${tree}`,
      `workflowCommit=${tree}`,
      'targetRef=refs/heads/master',
      `requestSha256=${requestSha256}`,
      `targetAttestationBlob=${targetBlob}`
    ].join('\n') + '\n');
    expect(result.stdout).not.toContain('canary-target.example.test');
    expect(result.stdout).not.toContain(endpoint);
    expect(result.stdout).not.toContain(keyCanary);
    expect(result.stdout).not.toContain('error.input');
    expect(result.stdout).not.toContain('Error:');
    expect(result.stdout).not.toContain('    at ');
    expect(readFileSync(outputPath, 'utf8')).toBe('');
  });

  it('reports UNKNOWN and exits nonzero without writing GITHUB_OUTPUT', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-unknown-'));
    temporaryDirectories.push(directory);
    const requestPath = join(directory, 'request.json');
    const outputPath = join(directory, 'github-output');
    const requestContents = JSON.stringify({targetRef: 'refs/heads/master'});
    writeFileSync(requestPath, requestContents);
    writeFileSync(outputPath, '');
    const workflowCommit = '0'.repeat(40);
    const result = spawnSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'diagnose-target',
      '--request', requestPath,
      '--workflow-commit', workflowCommit
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {...process.env, GITHUB_OUTPUT: outputPath}
    });
    const requestSha256 = createHash('sha256').update(requestContents).digest('hex');

    expect(result.status).toBe(1);
    expect(result.stderr).toBe('');
    expect(result.stdout).toBe([
      'failureCode=UNKNOWN',
      `imageOS=${process.env.ImageOS && /^[a-z0-9]{1,32}$/.test(process.env.ImageOS) ? process.env.ImageOS : 'invalid'}`,
      `imageVersion=${process.env.ImageVersion && /^[0-9.]{1,32}$/.test(process.env.ImageVersion) ? process.env.ImageVersion : 'invalid'}`,
      `node=${process.version}`,
      `openssl=${process.versions.openssl}`,
      `workflowCommit=${workflowCommit}`,
      'targetRef=refs/heads/master',
      `requestSha256=${requestSha256}`
    ].join('\n') + '\n');
    expect(readFileSync(outputPath, 'utf8')).toBe('');
  });

  it('rejects target, endpoint and key path override flags', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-overrides-'));
    temporaryDirectories.push(directory);
    const requestPath = join(directory, 'request.json');
    const outputPath = join(directory, 'github-output');
    writeFileSync(requestPath, JSON.stringify({targetRef: 'refs/heads/master'}));
    writeFileSync(outputPath, '');
    const result = spawnSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'diagnose-target',
      '--request', requestPath,
      '--workflow-commit', currentCommit(),
      '--target-ref', 'refs/tags/release/canary',
      '--endpoint', 'wss://canary-target.example.test/apiws?canary=query',
      '--key-file', '/canary-key/private.pem'
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {...process.env, GITHUB_OUTPUT: outputPath}
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toBe('');
    expect(result.stdout.trimEnd().split('\n')[0]).toBe('failureCode=UNKNOWN');
    expect(result.stdout).not.toContain('canary-target.example.test');
    expect(result.stdout).not.toContain('/canary-key/private.pem');
    expect(readFileSync(outputPath, 'utf8')).toBe('');
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

function previousTargetTree(directory) {
  const gitDirectory = join(directory, 'previous-target.git');
  execFileSync('git', ['init', '--bare', '--quiet', gitDirectory], {cwd: repositoryRoot});

  const previousTarget = JSON.parse(readFileSync(join(repositoryRoot, REVIEWED_PRIVATE_TARGET), 'utf8'));
  previousTarget.MTPROTO_PRIVATE_ENDPOINT = 'wss://previous.example.test:2443/apiws';
  const blob = execFileSync('git', ['--git-dir', gitDirectory, 'hash-object', '-w', '--stdin'], {
    input: JSON.stringify(previousTarget, null, 2) + '\n',
    encoding: 'utf8'
  }).trim();
  const targetTree = execFileSync('git', ['--git-dir', gitDirectory, 'mktree'], {
    input: `100644 blob ${blob}\tprivate-mtproto-target.json\n`,
    encoding: 'utf8'
  }).trim();
  const tree = execFileSync('git', ['--git-dir', gitDirectory, 'mktree'], {
    input: `040000 tree ${targetTree}\tci\n`,
    encoding: 'utf8'
  }).trim();
  const repositoryObjectDirectory = execFileSync('git', ['rev-parse', '--git-path', 'objects'], {
    cwd: repositoryRoot,
    encoding: 'utf8'
  }).trim();

  return {
    tree,
    objectDirectory: join(gitDirectory, 'objects'),
    alternateObjectDirectory: resolve(repositoryRoot, repositoryObjectDirectory)
  };
}

function privateTargetTreeWithOverrides(directory, endpoint, keyContents) {
  const gitDirectory = join(directory, 'diagnostic-target.git');
  execFileSync('git', ['init', '--bare', '--quiet', gitDirectory], {cwd: repositoryRoot});
  const repositoryObjectDirectory = resolve(repositoryRoot, execFileSync('git', ['rev-parse', '--git-path', 'objects'], {
    cwd: repositoryRoot,
    encoding: 'utf8'
  }).trim());
  const gitEnvironment = {
    GIT_DIR: gitDirectory,
    GIT_OBJECT_DIRECTORY: join(gitDirectory, 'objects'),
    GIT_ALTERNATE_OBJECT_DIRECTORIES: repositoryObjectDirectory
  };
  const gitOptions = {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: {...process.env, ...gitEnvironment}
  };
  const reviewedTarget = JSON.parse(readFileSync(join(repositoryRoot, REVIEWED_PRIVATE_TARGET), 'utf8'));
  reviewedTarget.MTPROTO_PRIVATE_ENDPOINT = endpoint;
  reviewedTarget.MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE = 'ci/canary-private-target-public.pem';
  reviewedTarget.publicKeySha256 = createHash('sha256').update(keyContents).digest('hex');
  const targetBlob = execFileSync('git', ['hash-object', '-w', '--stdin'], {
    ...gitOptions,
    input: JSON.stringify(reviewedTarget, null, 2) + '\n'
  }).trim();
  const keyBlob = execFileSync('git', ['hash-object', '-w', '--stdin'], {
    ...gitOptions,
    input: keyContents
  }).trim();
  const baseCommit = currentCommit();
  execFileSync('git', ['read-tree', baseCommit], gitOptions);
  execFileSync('git', ['update-index', '--add', '--cacheinfo', `100644,${targetBlob},${REVIEWED_PRIVATE_TARGET}`], gitOptions);
  execFileSync('git', ['update-index', '--add', '--cacheinfo', `100644,${keyBlob},ci/canary-private-target-public.pem`], gitOptions);
  const tree = execFileSync('git', ['write-tree'], gitOptions).trim();

  return {tree, targetBlob, gitEnvironment};
}
