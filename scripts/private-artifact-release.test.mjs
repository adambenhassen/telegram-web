import {execFileSync, spawnSync} from 'node:child_process';
import {createHash, createPublicKey, generateKeyPairSync} from 'node:crypto';
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
import {pathToFileURL} from 'node:url';
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
const privateArtifactWorkflowPath = join(repositoryRoot, '.github/workflows/private-artifact.yml');
const privateArtifactWorkflowText = readFileSync(privateArtifactWorkflowPath, 'utf8');
const pinnedSetupNodeAction = 'uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0';
const pinnedNodeVersion = 'node-version: 24.18.0';
const nodeVersionCheck = `test "$(node --version)" = 'v24.18.0'`;

function privateWorkflowJob(workflow, name) {
  const header = `  ${name}:\n`;
  const start = workflow.indexOf(header);
  if(start === -1) throw new Error(`Missing workflow job: ${name}`);
  const contentStart = start + header.length;
  const remainder = workflow.slice(contentStart);
  const nextJob = remainder.search(/^  [a-z][a-z0-9-]*:\n/m);
  return workflow.slice(start, nextJob === -1 ? undefined : contentStart + nextJob);
}

function privateWorkflowStep(job, name) {
  const header = `      - name: ${name}\n`;
  const start = job.indexOf(header);
  if(start === -1) throw new Error(`Missing workflow step: ${name}`);
  const contentStart = start + header.length;
  const remainder = job.slice(contentStart);
  const nextStep = remainder.search(/^      - name: /m);
  return job.slice(start, nextStep === -1 ? undefined : contentStart + nextStep);
}

function movePrivateWorkflowStepBefore(job, stepName, targetName) {
  const step = privateWorkflowStep(job, stepName);
  const stepStart = job.indexOf(`      - name: ${stepName}\n`);
  const withoutStep = job.slice(0, stepStart) + job.slice(stepStart + step.length);
  const targetStart = withoutStep.indexOf(`      - name: ${targetName}\n`);
  if(targetStart === -1) throw new Error(`Missing workflow step: ${targetName}`);
  return withoutStep.slice(0, targetStart) + step + withoutStep.slice(targetStart);
}

function assertPinnedNodeSetup(step, {allowPnpmCache = false} = {}) {
  const lines = step.split('\n').map((line) => line.trim());
  const setupActionLines = lines.filter((line) => line.startsWith('uses: actions/setup-node@'));
  const versionLines = lines.filter((line) => line.startsWith('node-version:'));
  const cacheLines = lines.filter((line) => line.startsWith('cache'));

  if(setupActionLines.length !== 1 || setupActionLines[0] !== pinnedSetupNodeAction) {
    throw new Error('setup-node must use the reviewed v4.4.0 SHA');
  }
  if(versionLines.length !== 1 || versionLines[0] !== pinnedNodeVersion) {
    throw new Error('setup-node must select the literal Node.js 24.18.0 version');
  }
  if(lines.some((line) => line.startsWith('node-version-file:') || line.startsWith('check-latest:'))) {
    throw new Error('setup-node must not derive or update the selected runtime');
  }
  if(!allowPnpmCache && cacheLines.length > 0) throw new Error('setup-node cache is forbidden before validation');
  if(allowPnpmCache && (cacheLines.length !== 1 || cacheLines[0] !== 'cache: pnpm')) {
    throw new Error('only the later pnpm cache is allowed');
  }
  if(lines.some((line) => /^(registry-url|always-auth|scope|token):/i.test(line)) ||
    /NODE_AUTH_TOKEN|npm_config_/i.test(step)) {
    throw new Error('setup-node must not configure registry authentication');
  }
}

function assertGuardedNodeInvocation(step, invocation) {
  const lines = step.split('\n');
  const runLine = lines.findIndex((line) => line.trim() === 'run: |');
  if(runLine === -1) throw new Error('Node invocation must use a literal shell block');
  const commands = lines.slice(runLine + 1).map((line) => line.trim()).filter(Boolean);
  const nodeCommands = commands.filter((command) => /^node(?:\s|$)/.test(command));
  if(commands[0] !== nodeVersionCheck) throw new Error('Node version must be checked immediately before invocation');
  if(nodeCommands.length !== 1 || !commands[1]?.startsWith(invocation)) {
    throw new Error(`Missing or unguarded Node invocation: ${invocation}`);
  }
}

function assertPrivateBuildDependencyBoundary(job) {
  const runtimeSetup = privateWorkflowStep(job, 'Set up Node.js 24.18.0 before target validation');
  const preValidation = privateWorkflowStep(job, 'Validate the immutable target before installation');
  const pnpmSetup = privateWorkflowStep(job, 'Set up pnpm');
  const cachedNodeSetup = privateWorkflowStep(job, 'Set up Node.js with pnpm cache');
  const install = privateWorkflowStep(job, 'Install dependencies');
  const postValidation = privateWorkflowStep(job, 'Revalidate the immutable target after installation');
  const positions = [runtimeSetup, preValidation, pnpmSetup, cachedNodeSetup, install, postValidation]
    .map((step) => job.indexOf(step));

  if(positions.some((position) => position === -1) || positions.some((position, index) =>
    index > 0 && position <= positions[index - 1]
  )) {
    throw new Error('Private build setup, validation, cache, and install order is unsafe');
  }

  const beforeValidation = job.slice(0, positions[1]);
  if(/pnpm\/action-setup|actions\/cache@|^\s*cache[\w-]*\s*:|pnpm install/m.test(beforeValidation)) {
    throw new Error('Dependency setup, cache, and install must follow pre-install validation');
  }

  assertPinnedNodeSetup(runtimeSetup);
  assertPinnedNodeSetup(cachedNodeSetup, {allowPnpmCache: true});
}

describe('private artifact workflow Node runtime', () => {
  const guardedInvocations = [
    [
      'publication preparation',
      'publication-prepare',
      'Set up Node.js 24.18.0',
      'Enforce the reviewed allowlist before installation',
      'node scripts/private-artifact-release.mjs prepare'
    ],
    [
      'pre-install target validation',
      'private-build',
      'Set up Node.js 24.18.0 before target validation',
      'Validate the immutable target before installation',
      'node scripts/private-artifact-release.mjs validate-target'
    ],
    [
      'post-install target validation',
      'private-build',
      'Set up Node.js 24.18.0 before target validation',
      'Revalidate the immutable target after installation',
      'node scripts/private-artifact-release.mjs validate-target'
    ],
    [
      'isolated publisher verification',
      'private-publish',
      'Set up Node.js 24.18.0',
      'Reverify the downloaded unit in the isolated publisher',
      'node "$RUNNER_TEMP/private-target-snapshot/publisher-verify.mjs"'
    ]
  ];
  const primaryRuntimeSetups = [
    ['publication-prepare', 'Set up Node.js 24.18.0'],
    ['private-build', 'Set up Node.js 24.18.0 before target validation'],
    ['private-publish', 'Set up Node.js 24.18.0']
  ];

  it.each(guardedInvocations)('pins and checks Node before %s', (_label, jobName, setupName, invocationName, command) => {
    const job = privateWorkflowJob(privateArtifactWorkflowText, jobName);
    const setup = privateWorkflowStep(job, setupName);
    const invocation = privateWorkflowStep(job, invocationName);

    assertPinnedNodeSetup(setup);
    assertGuardedNodeInvocation(invocation, command);
    expect(job.indexOf(setup)).toBeLessThan(job.indexOf(invocation));
  });

  it.each(primaryRuntimeSetups)('rejects an indirect runtime pin in %s', (jobName, setupName) => {
    const job = privateWorkflowJob(privateArtifactWorkflowText, jobName);
    const setup = privateWorkflowStep(job, setupName);
    const changedVersion = setup.replace(pinnedNodeVersion, 'node-version-file: .nvmrc');

    expect(changedVersion).not.toBe(setup);
    expect(() => assertPinnedNodeSetup(changedVersion)).toThrow(/literal Node\.js 24\.18\.0/);
  });

  it.each(primaryRuntimeSetups)('rejects cache access in the pre-validation runtime setup for %s', (jobName, setupName) => {
    const job = privateWorkflowJob(privateArtifactWorkflowText, jobName);
    const setup = privateWorkflowStep(job, setupName);
    const withCache = setup.replace(pinnedNodeVersion, `${pinnedNodeVersion}\n          cache: pnpm`);

    expect(() => assertPinnedNodeSetup(withCache)).toThrow(/cache is forbidden/);
  });

  it.each(primaryRuntimeSetups)('rejects registry authentication overrides in %s', (jobName, setupName) => {
    const job = privateWorkflowJob(privateArtifactWorkflowText, jobName);
    const setup = privateWorkflowStep(job, setupName);
    const withRegistry = setup.replace(pinnedNodeVersion, `${pinnedNodeVersion}\n          registry-url: https://registry.example.test`);

    expect(() => assertPinnedNodeSetup(withRegistry)).toThrow(/registry authentication/);
  });

  it.each(guardedInvocations)('rejects a missing runtime check before %s', (_label, jobName, _setupName, invocationName, command) => {
    const job = privateWorkflowJob(privateArtifactWorkflowText, jobName);
    const invocation = privateWorkflowStep(job, invocationName);
    const withoutCheck = invocation.replace(`${nodeVersionCheck}\n`, '');

    expect(() => assertGuardedNodeInvocation(withoutCheck, command)).toThrow(/checked immediately before/);
  });

  it('keeps pnpm setup and its supported cache after immutable target validation', () => {
    const job = privateWorkflowJob(privateArtifactWorkflowText, 'private-build');
    assertPrivateBuildDependencyBoundary(job);

    const cachedSetup = privateWorkflowStep(job, 'Set up Node.js with pnpm cache');
    expect(cachedSetup).toContain('cache: pnpm');
    expect(privateWorkflowStep(job, 'Check out the allowlisted target commit')).toContain('persist-credentials: false');
  });

  it.each(['Set up pnpm', 'Set up Node.js with pnpm cache', 'Install dependencies'])(
    'rejects moving %s before immutable target validation',
    (stepName) => {
      const job = privateWorkflowJob(privateArtifactWorkflowText, 'private-build');
      const unsafeOrder = movePrivateWorkflowStepBefore(job, stepName, 'Validate the immutable target before installation');

      expect(() => assertPrivateBuildDependencyBoundary(unsafeOrder)).toThrow(/order is unsafe/);
    }
  );

  it('rejects a standalone dependency cache before immutable target validation', () => {
    const job = privateWorkflowJob(privateArtifactWorkflowText, 'private-build');
    const withEarlyCache = job.replace(
      '      - name: Validate the immutable target before installation\n',
      '      - name: Restore pnpm cache\n        uses: actions/cache@v4\n\n      - name: Validate the immutable target before installation\n'
    );

    expect(withEarlyCache).not.toBe(job);
    expect(() => assertPrivateBuildDependencyBoundary(withEarlyCache)).toThrow(/must follow pre-install validation/);
  });

  it('keeps the isolated publisher credential-free and adjacent to upload after verification', () => {
    const job = privateWorkflowJob(privateArtifactWorkflowText, 'private-publish');
    const runtimeSetup = privateWorkflowStep(job, 'Set up Node.js 24.18.0');
    const firstDownload = privateWorkflowStep(job, 'Download the verified artifact');
    const reverify = privateWorkflowStep(job, 'Reverify the downloaded unit in the isolated publisher');
    const upload = privateWorkflowStep(job, 'Publish artifact and sidecar as one release unit');

    expect(job.indexOf(runtimeSetup)).toBeLessThan(job.indexOf(firstDownload));
    expect(job).not.toContain('actions/checkout@');
    expect(job).not.toContain('pnpm install');
    expect(job).not.toContain('pnpm/action-setup@');
    expect(job.indexOf(upload)).toBe(job.indexOf(reverify) + reverify.length);
  });

  it('selects Node after the credential-free checkout in publication preparation', () => {
    const job = privateWorkflowJob(privateArtifactWorkflowText, 'publication-prepare');
    const checkout = privateWorkflowStep(job, 'Check out the reviewed workflow commit');
    const setup = privateWorkflowStep(job, 'Set up Node.js 24.18.0');

    expect(checkout).toContain('persist-credentials: false');
    expect(job.indexOf(checkout)).toBeLessThan(job.indexOf(setup));
  });
});

afterAll(() => {
  for(const directory of temporaryDirectories) {
    rmSync(directory, {recursive: true, force: true});
  }
});

function writeDiagnosticKey(directory, contents, name = 'canary-public-key.pem') {
  const keyPath = join(directory, name);
  writeFileSync(keyPath, contents);
  return keyPath;
}

function publicKeyPem(label, der) {
  const payload = der.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${payload}\n-----END ${label}-----\n`;
}

function targetFailureCase(code, directory) {
  const keyContents = readFileSync(resolve(repositoryRoot, 'scripts/fixtures/private-mtproto-public.pem'), 'utf8');
  const validKeyPath = writeDiagnosticKey(directory, keyContents, 'canary-valid-public-key.pem');
  const baseEnvironment = {
    MTPROTO_TARGET_MODE: 'private',
    MTPROTO_PRIVATE_ENDPOINT: 'wss://canary-target.example.test:2443/apiws',
    MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: validKeyPath
  };
  const withOverrides = (overrides = {}) => ({...baseEnvironment, ...overrides});
  const keyEnvironment = (contents) => withOverrides({
    MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: writeDiagnosticKey(directory, contents)
  });

  switch(code) {
    case 'MODE_INVALID':
      return {environment: withOverrides({MTPROTO_TARGET_MODE: 'canary-mode'})};
    case 'FIELDS_MISSING':
      return {environment: withOverrides({MTPROTO_PRIVATE_ENDPOINT: ' '})};
    case 'FIELD_UNRECOGNIZED':
      return {environment: withOverrides({MTPROTO_PRIVATE_EXTRA: 'CANARY-UNRECOGNIZED-SECRET'})};
    case 'ENDPOINT_PREFIX':
      return {environment: withOverrides({MTPROTO_PRIVATE_ENDPOINT: 'https://canary-target.example.test/apiws?canary=query'})};
    case 'ENDPOINT_PARSE':
      return {environment: withOverrides({MTPROTO_PRIVATE_ENDPOINT: 'wss://canary-target.example.test:bad/apiws?canary=query'})};
    case 'ENDPOINT_SCHEME':
      return {environment: baseEnvironment, fault: code};
    case 'ENDPOINT_CREDENTIALS':
      return {environment: withOverrides({MTPROTO_PRIVATE_ENDPOINT: 'wss://canary-user:canary-password@canary-target.example.test/apiws'})};
    case 'ENDPOINT_QUERY':
      return {environment: withOverrides({MTPROTO_PRIVATE_ENDPOINT: 'wss://canary-target.example.test/apiws?canary=query'})};
    case 'ENDPOINT_FRAGMENT':
      return {environment: withOverrides({MTPROTO_PRIVATE_ENDPOINT: 'wss://canary-target.example.test/apiws#canary-fragment'})};
    case 'ENDPOINT_EMPTY_HOST':
      return {environment: withOverrides({MTPROTO_PRIVATE_ENDPOINT: 'wss://./apiws'})};
    case 'ENDPOINT_TELEGRAM_ORG':
      return {environment: withOverrides({MTPROTO_PRIVATE_ENDPOINT: 'wss://telegram.org/apiws'})};
    case 'KEY_FILE_OPEN':
      return {environment: withOverrides({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: join(directory, 'canary-missing-key.pem')})};
    case 'KEY_FILE_SHAPE':
      return {environment: keyEnvironment('A'.repeat(16 * 1024 + 1))};
    case 'KEY_FILE_READ':
      return {environment: withOverrides({MTPROTO_PRIVATE_ENDPOINT: 'wss://canary-target.example.test/apiws'}), fault: code};
    case 'KEY_PRIVATE_MATERIAL':
      return {environment: keyEnvironment('-----BEGIN RSA PRIVATE KEY-----\nCANARY-PRIVATE-KEY-MATERIAL\n-----END RSA PRIVATE KEY-----\n')};
    case 'KEY_PEM_SHAPE':
      return {environment: keyEnvironment('CANARY-KEY-MATERIAL-NOT-PEM')};
    case 'KEY_BASE64_NONCANONICAL':
      return {environment: keyEnvironment(keyContents.replace('AQAB', 'AQAB='))};
    case 'KEY_PARSE':
      return {environment: keyEnvironment(publicKeyPem('PUBLIC KEY', Buffer.from([1, 2, 3])))};
    case 'KEY_DER_NONCANONICAL': {
      const der = createPublicKey(keyContents).export({format: 'der', type: 'pkcs1'});
      return {environment: keyEnvironment(publicKeyPem('RSA PUBLIC KEY', Buffer.concat([der, Buffer.from([1, 2, 3])]))) };
    }
    case 'KEY_JWK_MISSING': {
      const {publicKey} = generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
      return {environment: keyEnvironment(publicKey.export({format: 'pem', type: 'spki'}))};
    }
    case 'KEY_SIZE_EXPONENT': {
      const {publicKey} = generateKeyPairSync('rsa', {modulusLength: 1024});
      return {environment: keyEnvironment(publicKey.export({format: 'pem', type: 'pkcs1'}))};
    }
    default:
      throw new Error(`Unsupported diagnostic failure case: ${code}`);
  }
}

function writeDiagnosticFaultPreloader(directory) {
  const preloaderPath = join(directory, 'diagnostic-fault-preloader.mjs');
  writeFileSync(preloaderPath, [
    "import fs from 'node:fs';",
    "import {syncBuiltinESMExports} from 'node:module';",
    "import {URL as NativeURL} from 'node:url';",
    "if(process.env.DIAGNOSTIC_TEST_FAULT === 'ENDPOINT_SCHEME') {",
    '  globalThis.URL = class extends NativeURL { get protocol() { return \'https:\'; } };',
    "} else if(process.env.DIAGNOSTIC_TEST_FAULT === 'KEY_FILE_READ') {",
    '  const originalOpenSync = fs.openSync;',
    '  const originalReadSync = fs.readSync;',
    '  const keyDescriptors = new Set();',
    '  let injected = false;',
    '  fs.openSync = function(path, ...args) {',
    '    const descriptor = originalOpenSync.call(this, path, ...args);',
    "    if(typeof path === 'string' && path.endsWith('.pem') && path.includes('canary') && typeof args[0] === 'number' && (args[0] & fs.constants.O_NONBLOCK) !== 0) keyDescriptors.add(descriptor);",
    '    return descriptor;',
    '  };',
    '  fs.readSync = function(...args) {',
    '    if(keyDescriptors.has(args[0]) && !injected) {',
    '      injected = true;',
    '      const error = new Error(\'CANARY-READ-FAULT\');',
    "      error.code = 'EIO';",
    '      throw error;',
    '    }',
    '    return originalReadSync.apply(this, args);',
    '  };',
    '  syncBuiltinESMExports();',
    '}'
  ].join('\n') + '\n');
  return preloaderPath;
}

function runTargetDiagnosticHarness(directory, failureCase, provenance) {
  const harnessPath = join(directory, 'target-diagnostic-harness.mjs');
  const resolverUrl = pathToFileURL(resolve(repositoryRoot, 'scripts/mtproto-target.mjs')).href;
  const formatterUrl = pathToFileURL(resolve(repositoryRoot, 'scripts/private-artifact-release.mjs')).href;
  writeFileSync(harnessPath, [
    `import {resolveMtprotoTarget} from ${JSON.stringify(resolverUrl)};`,
    `import {formatTargetDiagnostic} from ${JSON.stringify(formatterUrl)};`,
    'let error;',
    'let failed = false;',
    'try { resolveMtprotoTarget(process.env); } catch(cause) { failed = true; error = cause; }',
    'const provenance = JSON.parse(process.env.DIAGNOSTIC_TEST_PROVENANCE);',
    'process.stdout.write(formatTargetDiagnostic({error, failed, provenance}) + String.fromCharCode(10));',
    'if(failed) process.exitCode = 1;'
  ].join('\n') + '\n');

  const inheritedEnvironment = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    name !== 'NODE_OPTIONS' && name !== 'MTPROTO_TARGET_MODE' && !name.startsWith('MTPROTO_PRIVATE_')
  ));
  const args = [];
  if(failureCase.fault) {
    args.push('--import', writeDiagnosticFaultPreloader(directory));
  }
  args.push(harnessPath);
  return spawnSync(process.execPath, args, {
    cwd: repositoryRoot,
    encoding: 'utf8',
    env: {
      ...inheritedEnvironment,
      ...failureCase.environment,
      ImageOS: 'ubuntu24',
      ImageVersion: '20260927.320.1',
      DIAGNOSTIC_TEST_FAULT: failureCase.fault || '',
      DIAGNOSTIC_TEST_PROVENANCE: JSON.stringify(provenance)
    }
  });
}

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
    diagnosticWorkflowCommit: 'e'.repeat(40),
    requestWorkflowCommit: 'b'.repeat(40),
    sourceCommit: 'a'.repeat(40),
    requestRunId: '37141749542',
    targetRef: 'refs/heads/master',
    requestSha256: 'c'.repeat(64),
    attestationBlob: 'd'.repeat(40),
    keyFileBlob: 'f'.repeat(40)
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
    'KEY_JWK_MISSING', 'KEY_SIZE_EXPONENT'
  ];
  const linePatterns = [
    /^failureCode=(?:NONE|MODE_INVALID|FIELDS_MISSING|FIELD_UNRECOGNIZED|ENDPOINT_PREFIX|ENDPOINT_PARSE|ENDPOINT_SCHEME|ENDPOINT_CREDENTIALS|ENDPOINT_QUERY|ENDPOINT_FRAGMENT|ENDPOINT_EMPTY_HOST|ENDPOINT_TELEGRAM_ORG|KEY_FILE_OPEN|KEY_FILE_SHAPE|KEY_FILE_READ|KEY_PRIVATE_MATERIAL|KEY_PEM_SHAPE|KEY_BASE64_NONCANONICAL|KEY_PARSE|KEY_DER_NONCANONICAL|KEY_JWK_MISSING|KEY_SIZE_EXPONENT|UNKNOWN)$/,
    /^opensslErrorCode=(?:ERR_OSSL_[A-Z0-9_]{1,56}|other)$/,
    /^imageOS=(?:[a-z0-9]{1,32}|invalid)$/,
    /^imageVersion=(?:[0-9.]{1,32}|invalid)$/,
    /^node=(?:v\d+\.\d+\.\d+|invalid)$/,
    /^openssl=(?:\d+\.\d+\.\d+[a-z0-9.+-]{0,16}|invalid)$/,
    /^diagnosticWorkflowCommit=(?:[0-9a-f]{40}|invalid)$/,
    /^requestWorkflowCommit=(?:[0-9a-f]{40}|invalid)$/,
    /^sourceCommit=(?:[0-9a-f]{40}|invalid)$/,
    /^requestRunId=(?:[0-9]{1,20}|invalid)$/,
    /^requestSha256=(?:[0-9a-f]{64}|invalid)$/,
    /^attestationBlob=(?:[0-9a-f]{40}|invalid)$/,
    /^keyFileBlob=(?:[0-9a-f]{40}|invalid)$/,
    /^targetRef=(?:refs\/heads\/master|invalid)$/
  ];

  function formatDiagnostic(options) {
    expect(typeof privateArtifactRelease.formatTargetDiagnostic).toBe('function');
    return privateArtifactRelease.formatTargetDiagnostic(options);
  }

  it.each(failureCodes)('captures the real %s validator failure using only allowlisted lines', (code) => {
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-canary-'));
    temporaryDirectories.push(directory);
    const endpoint = 'wss://canary-target.example.test:2443/apiws?canary=query';
    const keyCanary = 'Q0FOREVZLUtFWS1NQVRFUklBTC0xMjM0NTY3ODkwQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=';
    const failureCase = targetFailureCase(code, directory);
    const result = runTargetDiagnosticHarness(directory, failureCase, provenance);
    const output = result.stdout + result.stderr;
    const lines = result.stdout.trimEnd().split('\n');

    expect(result.status).toBe(1);
    expect(result.stderr).toBe('');
    const opensslLine = code === 'KEY_PARSE' ? lines[1] : undefined;
    if(opensslLine) expect(opensslLine).toMatch(linePatterns[1]);
    expect(output).toBe([
      `failureCode=${code}`,
      ...(opensslLine ? [opensslLine] : []),
      `imageOS=${runtime.imageOS}`,
      `imageVersion=${runtime.imageVersion}`,
      `node=${runtime.node}`,
      `openssl=${runtime.openssl}`,
      `diagnosticWorkflowCommit=${provenance.diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${provenance.requestWorkflowCommit}`,
      `sourceCommit=${provenance.sourceCommit}`,
      `requestRunId=${provenance.requestRunId}`,
      `requestSha256=${provenance.requestSha256}`,
      `attestationBlob=${provenance.attestationBlob}`,
      `keyFileBlob=${provenance.keyFileBlob}`,
      `targetRef=${provenance.targetRef}`
    ].join('\n') + '\n');
    for(const line of lines) {
      expect(linePatterns.some((pattern) => pattern.test(line))).toBe(true);
    }
    expect(output).not.toContain('canary');
    expect(output).not.toContain(endpoint);
    expect(output).not.toContain(keyCanary);
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
      `diagnosticWorkflowCommit=${provenance.diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${provenance.requestWorkflowCommit}`,
      `sourceCommit=${provenance.sourceCommit}`,
      `requestRunId=${provenance.requestRunId}`,
      `requestSha256=${provenance.requestSha256}`,
      `attestationBlob=${provenance.attestationBlob}`,
      `keyFileBlob=${provenance.keyFileBlob}`,
      `targetRef=${provenance.targetRef}`
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
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-key-parse-'));
    temporaryDirectories.push(directory);
    const keyPath = writeDiagnosticKey(directory, publicKeyPem('PUBLIC KEY', Buffer.from([1, 2, 3])));
    let error;
    try {
      resolveMtprotoTarget({
        MTPROTO_TARGET_MODE: 'private',
        MTPROTO_PRIVATE_ENDPOINT: 'wss://canary-target.example.test/apiws',
        MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath
      });
    } catch(cause) {
      error = cause;
    }
    expect(error).toMatchObject({code: 'KEY_PARSE'});
    const causeCode = error.cause?.code;
    const expectedOpenSslErrorCode = typeof causeCode === 'string' && /^ERR_OSSL_[A-Z0-9_]{1,56}$/.test(causeCode)
      ? causeCode
      : 'other';
    const output = formatDiagnostic({
      error,
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
      `opensslErrorCode=${expectedOpenSslErrorCode}`,
      'imageOS=invalid',
      'imageVersion=invalid',
      'node=invalid',
      'openssl=invalid',
      `diagnosticWorkflowCommit=${provenance.diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${provenance.requestWorkflowCommit}`,
      `sourceCommit=${provenance.sourceCommit}`,
      `requestRunId=${provenance.requestRunId}`,
      `requestSha256=${provenance.requestSha256}`,
      `attestationBlob=${provenance.attestationBlob}`,
      `keyFileBlob=${provenance.keyFileBlob}`,
      `targetRef=${provenance.targetRef}`
    ]);
    expect(output).not.toContain('private');
    expect(output).not.toContain('canary');
    expect(output).not.toContain(keyPath);
  });

  it('sanitizes untrusted provenance values before emitting them', () => {
    const output = formatDiagnostic({
      error: new Error('canary exception'),
      provenance: {
        diagnosticWorkflowCommit: 'canary-diagnostic-workflow',
        requestWorkflowCommit: 'canary-request-workflow',
        sourceCommit: 'canary-source',
        requestRunId: 'canary-run\nhost',
        targetRef: 'refs/heads/master\ncanary-host',
        requestSha256: 'canary-request',
        attestationBlob: 'canary-attestation-blob',
        keyFileBlob: 'canary-key-blob'
      },
      runtime
    });

    expect(output.split('\n')).toEqual([
      'failureCode=UNKNOWN',
      `imageOS=${runtime.imageOS}`,
      `imageVersion=${runtime.imageVersion}`,
      `node=${runtime.node}`,
      `openssl=${runtime.openssl}`,
      'diagnosticWorkflowCommit=invalid',
      'requestWorkflowCommit=invalid',
      'sourceCommit=invalid',
      'requestRunId=invalid',
      'requestSha256=invalid',
      'attestationBlob=invalid',
      'keyFileBlob=invalid',
      'targetRef=invalid'
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
    const requestWorkflowCommit = currentCommit();
    const diagnosticWorkflowCommit = 'e'.repeat(40);
    const requestRunId = '37141749542';
    const attestationBlob = execFileSync('git', [
      'rev-parse', '--verify', `${requestWorkflowCommit}:${REVIEWED_PRIVATE_TARGET}`
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8'
    }).trim();
    const keyFileBlob = execFileSync('git', [
      'rev-parse', '--verify', `${requestWorkflowCommit}:scripts/fixtures/private-mtproto-public.pem`
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8'
    }).trim();
    expect(attestationBlob).toBe('bd985171365ec77b3ecbe0fc1b6faf46b4ab2311');
    expect(keyFileBlob).toBe('e857e9c678defbf442e192fe9cbc6cd66589c734');
    const result = spawnSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'diagnose-target',
      '--request', requestPath,
      '--workflow-commit', requestWorkflowCommit
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GITHUB_SHA: diagnosticWorkflowCommit,
        PRIVATE_ARTIFACT_REQUEST_RUN_ID: requestRunId,
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
      `diagnosticWorkflowCommit=${diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${requestWorkflowCommit}`,
      `sourceCommit=${requestWorkflowCommit}`,
      `requestRunId=${requestRunId}`,
      `requestSha256=${requestSha256}`,
      `attestationBlob=${attestationBlob}`,
      `keyFileBlob=${keyFileBlob}`,
      'targetRef=refs/heads/master'
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
    const {tree, targetBlob, keyBlob, gitEnvironment} = privateTargetTreeWithOverrides(directory, endpoint, keyCanary);
    const diagnosticWorkflowCommit = 'e'.repeat(40);
    const requestRunId = '37141749542';
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
        GITHUB_SHA: diagnosticWorkflowCommit,
        PRIVATE_ARTIFACT_REQUEST_RUN_ID: requestRunId,
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
      `diagnosticWorkflowCommit=${diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${tree}`,
      `sourceCommit=${tree}`,
      `requestRunId=${requestRunId}`,
      `requestSha256=${requestSha256}`,
      `attestationBlob=${targetBlob}`,
      `keyFileBlob=${keyBlob}`,
      'targetRef=refs/heads/master'
    ].join('\n') + '\n');
    expect(result.stdout).not.toContain('canary-target.example.test');
    expect(result.stdout).not.toContain(endpoint);
    expect(result.stdout).not.toContain(keyCanary);
    expect(result.stdout).not.toContain('error.input');
    expect(result.stdout).not.toContain('Error:');
    expect(result.stdout).not.toContain('    at ');
    expect(readFileSync(outputPath, 'utf8')).toBe('');
  });

  it.each(['ENDPOINT_SCHEME', 'KEY_FILE_READ'])('captures real CLI %s faults without stderr leakage', (code) => {
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-fault-'));
    temporaryDirectories.push(directory);
    const requestPath = join(directory, 'request.json');
    const outputPath = join(directory, 'github-output');
    const requestContents = JSON.stringify({targetRef: 'refs/heads/master'});
    const endpoint = 'wss://canary-target.example.test:2443/apiws';
    const keyContents = readFileSync(join(repositoryRoot, 'scripts/fixtures/private-mtproto-public.pem'), 'utf8');
    writeFileSync(requestPath, requestContents);
    writeFileSync(outputPath, '');
    const {tree, targetBlob, keyBlob, gitEnvironment} = privateTargetTreeWithOverrides(directory, endpoint, keyContents);
    const diagnosticWorkflowCommit = 'e'.repeat(40);
    const requestRunId = '37141749542';
    const result = spawnSync(process.execPath, [
      '--import', writeDiagnosticFaultPreloader(directory),
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
        DIAGNOSTIC_TEST_FAULT: code,
        GITHUB_SHA: diagnosticWorkflowCommit,
        PRIVATE_ARTIFACT_REQUEST_RUN_ID: requestRunId,
        GITHUB_OUTPUT: outputPath,
        ImageOS: 'ubuntu24',
        ImageVersion: '20260927.320.1'
      }
    });
    const requestSha256 = createHash('sha256').update(requestContents).digest('hex');
    const expectedOutput = [
      `failureCode=${code}`,
      'imageOS=ubuntu24',
      'imageVersion=20260927.320.1',
      `node=${process.version}`,
      `openssl=${process.versions.openssl}`,
      `diagnosticWorkflowCommit=${diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${tree}`,
      `sourceCommit=${tree}`,
      `requestRunId=${requestRunId}`,
      `requestSha256=${requestSha256}`,
      `attestationBlob=${targetBlob}`,
      `keyFileBlob=${keyBlob}`,
      'targetRef=refs/heads/master'
    ].join('\n') + '\n';

    expect(result.status).toBe(1);
    expect(result.stderr).toBe('');
    expect(result.stdout + result.stderr).toBe(expectedOutput);
    for(const line of result.stdout.trimEnd().split('\n')) {
      expect(linePatterns.some((pattern) => pattern.test(line))).toBe(true);
    }
    expect(result.stdout).not.toContain('canary-target.example.test');
    expect(result.stdout).not.toContain(keyContents);
    expect(result.stdout).not.toContain('CANARY-READ-FAULT');
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
    const diagnosticWorkflowCommit = 'e'.repeat(40);
    const requestRunId = '37141749542';
    const result = spawnSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'diagnose-target',
      '--request', requestPath,
      '--workflow-commit', workflowCommit
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GITHUB_SHA: diagnosticWorkflowCommit,
        PRIVATE_ARTIFACT_REQUEST_RUN_ID: requestRunId,
        GITHUB_OUTPUT: outputPath
      }
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
      `diagnosticWorkflowCommit=${diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${workflowCommit}`,
      'sourceCommit=invalid',
      `requestRunId=${requestRunId}`,
      `requestSha256=${requestSha256}`,
      'attestationBlob=invalid',
      'keyFileBlob=invalid',
      'targetRef=refs/heads/master'
    ].join('\n') + '\n');
    expect(readFileSync(outputPath, 'utf8')).toBe('');
  });

  it('hashes request bytes before rejecting malformed JSON', () => {
    const directory = mkdtempSync(join(tmpdir(), 'private-target-diagnostic-request-'));
    temporaryDirectories.push(directory);
    const requestPath = join(directory, 'request.json');
    const outputPath = join(directory, 'github-output');
    const requestContents = '{"targetRef":"refs/heads/master"';
    const diagnosticWorkflowCommit = 'e'.repeat(40);
    const requestWorkflowCommit = currentCommit();
    const requestRunId = '37141749542';
    writeFileSync(requestPath, requestContents);
    writeFileSync(outputPath, '');
    const result = spawnSync(process.execPath, [
      'scripts/private-artifact-release.mjs',
      'diagnose-target',
      '--request', requestPath,
      '--workflow-commit', requestWorkflowCommit
    ], {
      cwd: repositoryRoot,
      encoding: 'utf8',
      env: {
        ...process.env,
        GITHUB_SHA: diagnosticWorkflowCommit,
        PRIVATE_ARTIFACT_REQUEST_RUN_ID: requestRunId,
        GITHUB_OUTPUT: outputPath
      }
    });

    expect(result.status).toBe(1);
    expect(result.stderr).toBe('');
    expect(result.stdout).toBe([
      'failureCode=UNKNOWN',
      `imageOS=${process.env.ImageOS && /^[a-z0-9]{1,32}$/.test(process.env.ImageOS) ? process.env.ImageOS : 'invalid'}`,
      `imageVersion=${process.env.ImageVersion && /^[0-9.]{1,32}$/.test(process.env.ImageVersion) ? process.env.ImageVersion : 'invalid'}`,
      `node=${process.version}`,
      `openssl=${process.versions.openssl}`,
      `diagnosticWorkflowCommit=${diagnosticWorkflowCommit}`,
      `requestWorkflowCommit=${requestWorkflowCommit}`,
      'sourceCommit=invalid',
      `requestRunId=${requestRunId}`,
      `requestSha256=${createHash('sha256').update(requestContents).digest('hex')}`,
      'attestationBlob=invalid',
      'keyFileBlob=invalid',
      'targetRef=invalid'
    ].join('\n') + '\n');
    for(const line of result.stdout.trimEnd().split('\n')) {
      expect(linePatterns.some((pattern) => pattern.test(line))).toBe(true);
    }
    expect(result.stdout).not.toContain('{"targetRef"');
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

  return {tree, targetBlob, keyBlob, gitEnvironment};
}
