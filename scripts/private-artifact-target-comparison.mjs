import {execFileSync, spawnSync} from 'node:child_process';
import {lstatSync, readFileSync, readdirSync, writeFileSync} from 'node:fs';
import {dirname, join, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  assertTrustedWorkflowRun,
  MASTER_REF,
  readPublicationRequest,
  REVIEWED_PRIVATE_TARGET,
  resolvePublicationTarget
} from './private-artifact-release.mjs';

export const REQUEST_SHA256 = '4294d28b2f9e8f36fe7879974c5b6e472f2972d98a8b552e6290a45ebec0bbb0';
export const ATTESTATION_BLOB = 'bd985171365ec77b3ecbe0fc1b6faf46b4ab2311';
export const KEY_FILE_BLOB = 'e857e9c678defbf442e192fe9cbc6cd66589c734';

const REQUEST_WORKFLOW_PATH = '.github/workflows/private-artifact-request.yml';
const REVIEWED_KEY_FILE = 'scripts/fixtures/private-mtproto-public.pem';
const ROOT_DIRECTORY = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const TRUSTED_DIAGNOSTIC_CODES = new Set([
  'NONE',
  'MODE_INVALID',
  'FIELDS_MISSING',
  'FIELD_UNRECOGNIZED',
  'ENDPOINT_PREFIX',
  'ENDPOINT_PARSE',
  'ENDPOINT_SCHEME',
  'ENDPOINT_CREDENTIALS',
  'ENDPOINT_QUERY',
  'ENDPOINT_FRAGMENT',
  'ENDPOINT_EMPTY_HOST',
  'ENDPOINT_TELEGRAM_ORG',
  'KEY_FILE_OPEN',
  'KEY_FILE_SHAPE',
  'KEY_FILE_READ',
  'KEY_PRIVATE_MATERIAL',
  'KEY_PEM_SHAPE',
  'KEY_BASE64_NONCANONICAL',
  'KEY_PARSE',
  'KEY_DER_NONCANONICAL',
  'KEY_JWK_MISSING',
  'KEY_SIZE_EXPONENT',
  'UNKNOWN'
]);

class ComparisonError extends Error {}

function fail(message) {
  throw new ComparisonError(message);
}

function assertExactFields(value, fields) {
  if(!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('comparison data is invalid');
  }

  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if(JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail('comparison data is invalid');
  }
}

function assertRunId(value) {
  if(typeof value !== 'string' || !/^[0-9]{1,20}$/.test(value)) {
    fail('request run id is invalid');
  }
  return value;
}

function assertCommit(value) {
  if(typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) {
    fail('request run commit is invalid');
  }
  return value;
}

function assertRequestIsAncestor(rootDirectory, requestCommit, diagnosticCommit) {
  try {
    execFileSync('git', ['merge-base', '--is-ancestor', requestCommit, diagnosticCommit], {
      cwd: rootDirectory,
      stdio: 'ignore'
    });
  } catch{
    fail('request run is outside diagnostic history');
  }
}

export function validateRequestRunMetadata({
  metadata,
  requestRunId,
  repository,
  diagnosticWorkflowCommit,
  rootDirectory = ROOT_DIRECTORY
}) {
  assertRunId(requestRunId);
  assertCommit(diagnosticWorkflowCommit);
  if(!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    fail('request run metadata is invalid');
  }

  const metadataRunId = String(metadata.id);
  if(!/^[0-9]{1,20}$/.test(metadataRunId) || BigInt(metadataRunId) !== BigInt(requestRunId)) {
    fail('request run metadata is invalid');
  }
  if(metadata.event !== 'repository_dispatch' || metadata.path !== REQUEST_WORKFLOW_PATH) {
    fail('request run metadata is invalid');
  }
  if(!repository || metadata.head_repository?.full_name !== repository) {
    fail('request run metadata is invalid');
  }

  const requestWorkflowCommit = assertCommit(metadata.head_sha);
  try {
    // The publisher receives this trusted request as a workflow_run event.
    assertTrustedWorkflowRun({
      eventName: 'workflow_run',
      workflowName: metadata.name,
      headBranch: metadata.head_branch,
      conclusion: metadata.conclusion
    });
  } catch{
    fail('request run metadata is invalid');
  }

  assertRequestIsAncestor(rootDirectory, requestWorkflowCommit, diagnosticWorkflowCommit);
  return {
    requestRunId,
    requestWorkflowCommit,
    diagnosticWorkflowCommit
  };
}

function assertRequestRunContext(value) {
  assertExactFields(value, [
    'requestRunId',
    'requestWorkflowCommit',
    'diagnosticWorkflowCommit'
  ]);
  return {
    requestRunId: assertRunId(value.requestRunId),
    requestWorkflowCommit: assertCommit(value.requestWorkflowCommit),
    diagnosticWorkflowCommit: assertCommit(value.diagnosticWorkflowCommit)
  };
}

function requestArtifactPath(artifactDirectory) {
  let directory;
  try {
    directory = lstatSync(artifactDirectory);
  } catch{
    fail('request artifact is invalid');
  }
  if(!directory.isDirectory() || directory.isSymbolicLink()) {
    fail('request artifact is invalid');
  }

  let entries;
  try {
    entries = readdirSync(artifactDirectory);
  } catch{
    fail('request artifact is invalid');
  }
  if(entries.length !== 1 || entries[0] !== 'request.json') {
    fail('request artifact is invalid');
  }

  const requestPath = join(artifactDirectory, 'request.json');
  let requestFile;
  try {
    requestFile = lstatSync(requestPath);
  } catch{
    fail('request artifact is invalid');
  }
  if(!requestFile.isFile() || requestFile.isSymbolicLink() || requestFile.size > 1024) {
    fail('request artifact is invalid');
  }
  return requestPath;
}

export function assertFixedComparisonValues({requestSha256, attestationBlob, keyFileBlob}) {
  if(requestSha256 !== REQUEST_SHA256) {
    fail('request hash does not match');
  }
  if(attestationBlob !== ATTESTATION_BLOB) {
    fail('attestation blob does not match');
  }
  if(keyFileBlob !== KEY_FILE_BLOB) {
    fail('key file blob does not match');
  }
}

export function assertMasterTargetRef(targetRef) {
  if(targetRef !== MASTER_REF) {
    fail('request target is invalid');
  }
}

function gitBlobId(rootDirectory, commit, path) {
  try {
    return execFileSync('git', ['rev-parse', '--verify', `${commit}:${path}`], {
      cwd: rootDirectory,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
  } catch{
    fail('source provenance is invalid');
  }
}

export function verifyRequestArtifact({
  requestRunContext,
  artifactDirectory,
  rootDirectory = ROOT_DIRECTORY
}) {
  const run = assertRequestRunContext(requestRunContext);
  assertRequestIsAncestor(rootDirectory, run.requestWorkflowCommit, run.diagnosticWorkflowCommit);
  const requestPath = requestArtifactPath(artifactDirectory);

  let loadedRequest;
  let requestSha256;
  try {
    loadedRequest = readPublicationRequest(requestPath, {
      onHash(value) {
        requestSha256 = value;
        if(value !== REQUEST_SHA256) {
          fail('request hash does not match');
        }
      }
    });
  } catch(error) {
    if(error instanceof ComparisonError) throw error;
    fail('request artifact is invalid');
  }
  assertMasterTargetRef(loadedRequest.request.targetRef);

  let source;
  try {
    source = resolvePublicationTarget({
      rootDirectory,
      targetRef: loadedRequest.request.targetRef,
      workflowCommit: run.requestWorkflowCommit,
      silent: true
    });
  } catch{
    fail('source provenance is invalid');
  }

  const attestationBlob = gitBlobId(rootDirectory, source.commit, REVIEWED_PRIVATE_TARGET);
  const keyFileBlob = gitBlobId(rootDirectory, source.commit, REVIEWED_KEY_FILE);
  assertFixedComparisonValues({requestSha256, attestationBlob, keyFileBlob});

  return assertComparisonContext({
    diagnosticWorkflowCommit: run.diagnosticWorkflowCommit,
    requestWorkflowCommit: run.requestWorkflowCommit,
    sourceCommit: source.commit,
    requestRunId: run.requestRunId,
    requestSha256,
    attestationBlob,
    keyFileBlob,
    targetRef: source.ref
  });
}

export function assertComparisonContext(value) {
  assertExactFields(value, [
    'diagnosticWorkflowCommit',
    'requestWorkflowCommit',
    'sourceCommit',
    'requestRunId',
    'requestSha256',
    'attestationBlob',
    'keyFileBlob',
    'targetRef'
  ]);
  const context = {
    diagnosticWorkflowCommit: assertCommit(value.diagnosticWorkflowCommit),
    requestWorkflowCommit: assertCommit(value.requestWorkflowCommit),
    sourceCommit: assertCommit(value.sourceCommit),
    requestRunId: assertRunId(value.requestRunId),
    requestSha256: value.requestSha256,
    attestationBlob: value.attestationBlob,
    keyFileBlob: value.keyFileBlob,
    targetRef: value.targetRef
  };
  assertFixedComparisonValues(context);
  if(context.targetRef !== MASTER_REF) {
    fail('comparison target is invalid');
  }
  return context;
}

export function diagnosticChildEnvironment(environment, contextValue) {
  const context = assertComparisonContext(contextValue);
  if(typeof environment.RUNNER_TEMP !== 'string' || !environment.RUNNER_TEMP) {
    fail('diagnostic temporary directory is invalid');
  }

  const childEnvironment = {
    GITHUB_SHA: context.diagnosticWorkflowCommit,
    PRIVATE_ARTIFACT_REQUEST_RUN_ID: context.requestRunId,
    RUNNER_TEMP: environment.RUNNER_TEMP,
    TMPDIR: environment.RUNNER_TEMP
  };
  if(typeof environment.PATH === 'string') childEnvironment.PATH = environment.PATH;
  if(typeof environment.ImageOS === 'string') childEnvironment.ImageOS = environment.ImageOS;
  if(typeof environment.ImageVersion === 'string') childEnvironment.ImageVersion = environment.ImageVersion;
  return childEnvironment;
}

export function assertAllowlistedDiagnostic({stdout, stderr, status, context}) {
  if(typeof stdout !== 'string' || typeof stderr !== 'string' || stderr !== '' || ![0, 1].includes(status)) {
    fail('diagnostic output is invalid');
  }

  const lines = stdout.endsWith('\n') ? stdout.slice(0, -1).split('\n') : stdout.split('\n');
  const failureCode = lines[0]?.slice('failureCode='.length);
  if(!TRUSTED_DIAGNOSTIC_CODES.has(failureCode)) {
    fail('diagnostic output is invalid');
  }
  if((failureCode === 'NONE' && status !== 0) || (failureCode !== 'NONE' && status !== 1)) {
    fail('diagnostic output is invalid');
  }

  const runtimeOffset = failureCode === 'KEY_PARSE' ? 2 : 1;
  const expectedLines = [
    `failureCode=${failureCode}`,
    ...(failureCode === 'KEY_PARSE' ? [lines[1]] : []),
    lines[runtimeOffset],
    lines[runtimeOffset + 1],
    lines[runtimeOffset + 2],
    lines[runtimeOffset + 3],
    `diagnosticWorkflowCommit=${context.diagnosticWorkflowCommit}`,
    `requestWorkflowCommit=${context.requestWorkflowCommit}`,
    `sourceCommit=${context.sourceCommit}`,
    `requestRunId=${context.requestRunId}`,
    `requestSha256=${context.requestSha256}`,
    `attestationBlob=${context.attestationBlob}`,
    `keyFileBlob=${context.keyFileBlob}`,
    `targetRef=${MASTER_REF}`
  ];
  if(lines.length !== expectedLines.length || lines.some((line, index) => line !== expectedLines[index])) {
    fail('diagnostic output is invalid');
  }

  const runtimeLines = lines.slice(runtimeOffset, runtimeOffset + 4);
  const runtimePatterns = [
    /^imageOS=(?:[a-z0-9]{1,32}|invalid)$/,
    /^imageVersion=(?:[0-9.]{1,32}|invalid)$/,
    /^node=(?:v\d+\.\d+\.\d+|invalid)$/,
    /^openssl=(?:\d+\.\d+\.\d+[a-z0-9.+-]{0,16}|invalid)$/
  ];
  if(runtimeLines.some((line, index) => !runtimePatterns[index].test(line))) {
    fail('diagnostic output is invalid');
  }
  if(failureCode === 'KEY_PARSE' && !/^opensslErrorCode=(?:ERR_OSSL_[A-Z0-9_]{1,56}|other)$/.test(lines[1])) {
    fail('diagnostic output is invalid');
  }
}

function readJson(filePath) {
  try {
    return JSON.parse(readFileSync(filePath, 'utf8'));
  } catch{
    fail('comparison data is invalid');
  }
}

function writeJson(filePath, value) {
  writeFileSync(filePath, JSON.stringify(value) + '\n', {flag: 'wx', mode: 0o600});
}

function validateRunCommand(contextPath) {
  let metadata;
  try {
    metadata = JSON.parse(readFileSync(0, 'utf8'));
  } catch{
    fail('request run metadata is invalid');
  }
  const context = validateRequestRunMetadata({
    metadata,
    requestRunId: process.env.REQUEST_RUN_ID,
    repository: process.env.GITHUB_REPOSITORY,
    diagnosticWorkflowCommit: process.env.GITHUB_SHA
  });
  writeJson(contextPath, context);
}

function verifyRequestCommand(requestRunContextPath, artifactDirectory, comparisonContextPath) {
  const requestRunContext = assertRequestRunContext(readJson(requestRunContextPath));
  const context = verifyRequestArtifact({requestRunContext, artifactDirectory});
  writeJson(comparisonContextPath, context);
}

function runDiagnosticCommand(comparisonContextPath, artifactDirectory) {
  const expectedContext = assertComparisonContext(readJson(comparisonContextPath));
  const actualContext = verifyRequestArtifact({
    requestRunContext: {
      requestRunId: expectedContext.requestRunId,
      requestWorkflowCommit: expectedContext.requestWorkflowCommit,
      diagnosticWorkflowCommit: expectedContext.diagnosticWorkflowCommit
    },
    artifactDirectory
  });
  if(JSON.stringify(actualContext) !== JSON.stringify(expectedContext)) {
    fail('comparison provenance changed');
  }

  const requestPath = requestArtifactPath(artifactDirectory);
  let result;
  try {
    result = spawnSync(process.execPath, [
      join(ROOT_DIRECTORY, 'scripts/private-artifact-release.mjs'),
      'diagnose-target',
      '--request', requestPath,
      '--workflow-commit', actualContext.requestWorkflowCommit
    ], {
      cwd: ROOT_DIRECTORY,
      encoding: 'utf8',
      env: diagnosticChildEnvironment(process.env, actualContext)
    });
  } catch{
    fail('diagnostic did not complete');
  }
  if(result.error || result.signal) {
    fail('diagnostic did not complete');
  }

  assertAllowlistedDiagnostic({
    stdout: result.stdout,
    stderr: result.stderr,
    status: result.status,
    context: actualContext
  });
  process.stdout.write(result.stdout);
  process.exitCode = result.status;
}

function main() {
  const [command, ...args] = process.argv.slice(2);
  if(command === 'validate-run' && args.length === 1) {
    validateRunCommand(args[0]);
    return;
  }
  if(command === 'verify-request' && args.length === 3) {
    verifyRequestCommand(args[0], args[1], args[2]);
    return;
  }
  if(command === 'diagnose' && args.length === 2) {
    runDiagnosticCommand(args[0], args[1]);
    return;
  }
  fail('comparison command is invalid');
}

const invokedScript = process.argv[1] && resolve(process.argv[1]);
if(invokedScript === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch{
    process.exitCode = 1;
  }
}
