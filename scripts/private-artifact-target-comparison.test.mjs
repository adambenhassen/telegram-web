import {execFileSync, spawnSync} from 'node:child_process';
import {mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {afterAll, describe, expect, it} from 'vitest';
import {
  assertAllowlistedDiagnostic,
  assertFixedComparisonValues,
  assertMasterTargetRef,
  diagnosticChildEnvironment,
  KEY_FILE_BLOB,
  REQUEST_SHA256,
  ATTESTATION_BLOB,
  validateRequestRunMetadata,
  verifyRequestArtifact
} from './private-artifact-target-comparison.mjs';

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workflowPath = '.github/workflows/private-artifact-request.yml';
const repository = 'teagramhq/telegram-web';
const requestRunId = '37141749542';
const requestWorkflowCommit = '3ea229385f56f87d4b672423aee509f1ba3fc55b';
const diagnosticWorkflowCommit = execFileSync('git', ['rev-parse', '--verify', 'HEAD'], {
  cwd: repositoryRoot,
  encoding: 'utf8'
}).trim();
const temporaryDirectories = [];

afterAll(() => {
  for(const directory of temporaryDirectories) {
    rmSync(directory, {recursive: true, force: true});
  }
});

function temporaryDirectory(prefix = 'private-artifact-comparison-') {
  const directory = mkdtempSync(join(tmpdir(), prefix));
  temporaryDirectories.push(directory);
  return directory;
}

function trustedMetadata(overrides = {}) {
  return {
    id: Number(requestRunId),
    event: 'repository_dispatch',
    path: workflowPath,
    name: 'Private MTProto Artifact Request',
    head_branch: 'master',
    head_repository: {full_name: repository},
    conclusion: 'success',
    head_sha: requestWorkflowCommit,
    ...overrides
  };
}

function validateTrustedRun(metadata = trustedMetadata(), id = requestRunId) {
  return validateRequestRunMetadata({
    metadata,
    requestRunId: id,
    repository,
    diagnosticWorkflowCommit,
    rootDirectory: repositoryRoot
  });
}

function requestArtifact(contents = '{"targetRef":"refs/heads/master"}\n') {
  const directory = temporaryDirectory();
  const artifactDirectory = join(directory, 'artifact');
  mkdirSync(artifactDirectory);
  writeFileSync(join(artifactDirectory, 'request.json'), contents);
  return {directory, artifactDirectory};
}

function validContext() {
  return {
    diagnosticWorkflowCommit,
    requestWorkflowCommit,
    sourceCommit: requestWorkflowCommit,
    requestRunId,
    requestSha256: REQUEST_SHA256,
    attestationBlob: ATTESTATION_BLOB,
    keyFileBlob: KEY_FILE_BLOB,
    targetRef: 'refs/heads/master'
  };
}

describe('private artifact target comparison', () => {
  it('accepts a successful trusted request run in diagnostic history', () => {
    expect(validateTrustedRun()).toEqual({
      requestRunId,
      requestWorkflowCommit,
      diagnosticWorkflowCommit
    });
  });

  it.each([
    ['non-numeric request run id', trustedMetadata(), '37141749542;echo unsafe'],
    ['run id mismatch', trustedMetadata({id: 1}), requestRunId],
    ['wrong event', trustedMetadata({event: 'workflow_dispatch'}), requestRunId],
    ['wrong workflow path', trustedMetadata({path: '.github/workflows/untrusted.yml'}), requestRunId],
    ['wrong workflow name', trustedMetadata({name: 'Untrusted Request'}), requestRunId],
    ['wrong head branch', trustedMetadata({head_branch: 'feature'}), requestRunId],
    ['wrong head repository', trustedMetadata({head_repository: {full_name: 'attacker/repo'}}), requestRunId],
    ['unsuccessful conclusion', trustedMetadata({conclusion: 'failure'}), requestRunId],
    ['invalid head SHA', trustedMetadata({head_sha: 'not-a-commit'}), requestRunId]
  ])('rejects %s before request download', (_label, metadata, id) => {
    expect(() => validateTrustedRun(metadata, id)).toThrow();
  });

  it('rejects request commits outside the diagnostic history', () => {
    expect(() => validateTrustedRun(trustedMetadata({head_sha: 'a'.repeat(40)}))).toThrow();
  });

  it('accepts the exact request artifact and resolves its source at the request commit', () => {
    const {artifactDirectory} = requestArtifact();
    const context = verifyRequestArtifact({
      requestRunContext: validateTrustedRun(),
      artifactDirectory,
      rootDirectory: repositoryRoot
    });

    expect(context).toEqual(validContext());
  });

  it('rejects an artifact with extra files', () => {
    const {artifactDirectory} = requestArtifact();
    writeFileSync(join(artifactDirectory, 'extra.txt'), 'untrusted');

    expect(() => verifyRequestArtifact({
      requestRunContext: validateTrustedRun(),
      artifactDirectory,
      rootDirectory: repositoryRoot
    })).toThrow(/request artifact is invalid/);
  });

  it('rejects a symlink in place of request.json', () => {
    const directory = temporaryDirectory();
    const artifactDirectory = join(directory, 'artifact');
    mkdirSync(artifactDirectory);
    writeFileSync(join(artifactDirectory, 'target.json'), '{"targetRef":"refs/heads/master"}\n');
    symlinkSync('target.json', join(artifactDirectory, 'request.json'));

    expect(() => verifyRequestArtifact({
      requestRunContext: validateTrustedRun(),
      artifactDirectory,
      rootDirectory: repositoryRoot
    })).toThrow(/request artifact is invalid/);
  });

  it('rejects request.json larger than 1 KiB', () => {
    const {artifactDirectory} = requestArtifact('x'.repeat(1025));

    expect(() => verifyRequestArtifact({
      requestRunContext: validateTrustedRun(),
      artifactDirectory,
      rootDirectory: repositoryRoot
    })).toThrow(/request artifact is invalid/);
  });

  it('checks the request hash before parsing request bytes', () => {
    const {artifactDirectory} = requestArtifact('{');

    expect(() => verifyRequestArtifact({
      requestRunContext: validateTrustedRun(),
      artifactDirectory,
      rootDirectory: repositoryRoot
    })).toThrow(/request hash does not match/);
  });

  it.each([
    ['request hash', {requestSha256: '0'.repeat(64)}],
    ['attestation blob', {attestationBlob: '0'.repeat(40)}],
    ['key file blob', {keyFileBlob: '0'.repeat(40)}]
  ])('rejects a mismatched %s literal', (_label, mismatch) => {
    expect(() => assertFixedComparisonValues({
      requestSha256: REQUEST_SHA256,
      attestationBlob: ATTESTATION_BLOB,
      keyFileBlob: KEY_FILE_BLOB,
      ...mismatch
    })).toThrow();
  });

  it('accepts only the master target ref', () => {
    expect(() => assertMasterTargetRef('refs/heads/master')).not.toThrow();
    expect(() => assertMasterTargetRef('refs/heads/feature')).toThrow();
  });

  it('passes only fixed provenance and runtime values to the diagnostic process', () => {
    const environment = diagnosticChildEnvironment({
      PATH: '/usr/bin',
      RUNNER_TEMP: '/runner/temp',
      ImageOS: 'ubuntu26',
      ImageVersion: '20260927.149.1',
      GH_TOKEN: 'canary-token',
      GITHUB_TOKEN: 'canary-token',
      ACTIONS_RUNTIME_TOKEN: 'canary-token',
      GITHUB_OUTPUT: '/runner/output',
      MTPROTO_PRIVATE_ENDPOINT: 'wss://canary.example.test/apiws'
    }, validContext());

    expect(environment).toEqual({
      GITHUB_SHA: diagnosticWorkflowCommit,
      PRIVATE_ARTIFACT_REQUEST_RUN_ID: requestRunId,
      RUNNER_TEMP: '/runner/temp',
      TMPDIR: '/runner/temp',
      PATH: '/usr/bin',
      ImageOS: 'ubuntu26',
      ImageVersion: '20260927.149.1'
    });
  });

  it('emits only allowlisted diagnostic lines and rejects free-text output', () => {
    const context = validContext();
    const stdout = [
      'failureCode=NONE',
      'imageOS=ubuntu26',
      'imageVersion=20260927.149.1',
      `node=${process.version}`,
      `openssl=${process.versions.openssl}`,
      `diagnosticWorkflowCommit=${context.diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${context.requestWorkflowCommit}`,
      `sourceCommit=${context.sourceCommit}`,
      `requestRunId=${context.requestRunId}`,
      `requestSha256=${context.requestSha256}`,
      `attestationBlob=${context.attestationBlob}`,
      `keyFileBlob=${context.keyFileBlob}`,
      'targetRef=refs/heads/master'
    ].join('\n') + '\n';

    expect(() => assertAllowlistedDiagnostic({stdout, stderr: '', status: 0, context})).not.toThrow();
    expect(() => assertAllowlistedDiagnostic({
      stdout: stdout.replace('targetRef=refs/heads/master', 'endpoint=wss://canary.example.test'),
      stderr: '',
      status: 0,
      context
    })).toThrow(/diagnostic output is invalid/);
  });

  it('runs diagnose-target without tokens or GITHUB_OUTPUT and preserves its redacted output', () => {
    const {directory, artifactDirectory} = requestArtifact();
    const contextPath = join(directory, 'comparison.json');
    const outputPath = join(directory, 'github-output');
    writeFileSync(contextPath, JSON.stringify(validContext()));
    writeFileSync(outputPath, '');
    const result = spawnSync(process.execPath, [
      'scripts/private-artifact-target-comparison.mjs',
      'diagnose',
      contextPath,
      artifactDirectory
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        GITHUB_SHA: diagnosticWorkflowCommit,
        RUNNER_TEMP: directory,
        ImageOS: 'ubuntu26',
        ImageVersion: '20260927.149.1',
        GH_TOKEN: 'canary-token',
        GITHUB_TOKEN: 'canary-token',
        ACTIONS_RUNTIME_TOKEN: 'canary-token',
        GITHUB_OUTPUT: outputPath,
        MTPROTO_PRIVATE_ENDPOINT: 'wss://canary.example.test/apiws'
      }
    });

    expect(result.status).toBe(0);
    expect(result.stderr).toBe('');
    expect(result.stdout).toBe([
      'failureCode=NONE',
      'imageOS=ubuntu26',
      'imageVersion=20260927.149.1',
      `node=${process.version}`,
      `openssl=${process.versions.openssl}`,
      `diagnosticWorkflowCommit=${diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${requestWorkflowCommit}`,
      `sourceCommit=${requestWorkflowCommit}`,
      `requestRunId=${requestRunId}`,
      `requestSha256=${REQUEST_SHA256}`,
      `attestationBlob=${ATTESTATION_BLOB}`,
      `keyFileBlob=${KEY_FILE_BLOB}`,
      'targetRef=refs/heads/master'
    ].join('\n') + '\n');
    expect(result.stdout).not.toContain('canary');
    expect(readFileSync(outputPath, 'utf8')).toBe('');
  });

  it('defines one master-only, nonpublishing four-leg workflow', () => {
    const workflow = readFileSync(join(repositoryRoot, '.github/workflows/private-artifact-target-comparison.yml'), 'utf8');
    const inputBlock = workflow.match(/^  workflow_dispatch:\n    inputs:\n([\s\S]*?)^permissions:/m)?.[1];
    const inputNames = [...(inputBlock || '').matchAll(/^      ([a-z][a-z0-9_]*):/gm)].map((match) => match[1]);
    const steps = new Map(workflow.split(/^      - name: /m).slice(1).map((step) => [step.split('\n', 1)[0], step]));
    const stepNames = [...steps.keys()];
    const runBody = (step) => {
      const lines = step.split('\n');
      const start = lines.findIndex((line) => /^        run:/.test(line));
      return start === -1 ? '' : lines.slice(start + 1).join('\n');
    };

    expect(inputNames).toEqual(['request_run_id']);
    expect(workflow).toContain('if: github.ref == \'refs/heads/master\'');
    expect(workflow).toContain('fail-fast: false');
    expect(workflow).toContain('runner: ubuntu-24.04');
    expect(workflow).toContain('runner: ubuntu-26.04');
    expect(workflow.match(/node: image/g)).toHaveLength(2);
    expect(workflow.match(/node: pinned/g)).toHaveLength(2);
    expect(workflow).toContain('fetch-depth: 0');
    expect(workflow).toContain('persist-credentials: false');
    expect(workflow).toContain('node-version: 24.18.0');
    expect(workflow).not.toContain('cache:');
    expect(workflow).toContain('actions: read');
    expect(workflow).toContain('contents: read');
    expect(workflow).not.toMatch(/upload-artifact|GITHUB_OUTPUT|pnpm install|secrets\./);

    for(const name of ['Validate request run metadata', 'Download the data-only request artifact']) {
      expect(steps.get(name)).toContain('GH_TOKEN: ${{ github.token }}');
    }
    expect(stepNames.indexOf('Validate request run metadata')).toBeLessThan(stepNames.indexOf('Download the data-only request artifact'));
    expect(stepNames.indexOf('Download the data-only request artifact')).toBeLessThan(stepNames.indexOf('Verify request and resolved source provenance'));
    expect(stepNames.indexOf('Verify request and resolved source provenance')).toBeLessThan(stepNames.indexOf('Run redacted private-target diagnostic'));
    expect(steps.get('Run redacted private-target diagnostic')).not.toMatch(/GH_TOKEN|GITHUB_TOKEN|github\.token|secrets\./);
    for(const step of steps.values()) {
      const body = runBody(step);
      if(body) expect(body).not.toContain('${{');
    }
  });

  it('fetches git history for request ancestry validation in Pull Request CI', () => {
    const workflow = readFileSync(join(repositoryRoot, '.github/workflows/ci.yml'), 'utf8');
    const checkoutStep = workflow.split('      - name: Check out code\n')[1]?.split('\n      - name: ')[0];

    expect(checkoutStep).toContain('fetch-depth: 0');
  });
});
