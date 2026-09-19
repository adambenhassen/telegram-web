import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {
  appendFileSync,
  existsSync,
  readFileSync,
  statSync
} from 'node:fs';
import {dirname, isAbsolute, relative, resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {resolveMtprotoTarget} from './mtproto-target.mjs';
import {
  verifyPrivateArtifactCsp,
  verifyPrivateArtifactManifest
} from './private-artifact.mjs';

export const REVIEWED_PRIVATE_TARGET = 'ci/private-mtproto-target.json';
export const REVIEWED_RELEASE_REFS = 'ci/private-artifact-reviewed-release-refs.json';
export const PRIVATE_TARGET_VARIABLES = [
  'MTPROTO_TARGET_MODE',
  'MTPROTO_PRIVATE_ENDPOINT',
  'MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE'
];

const ROOT_DIRECTORY = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MASTER_REF = 'refs/heads/master';
const REVIEWED_RELEASE_REF_PATTERN = /^refs\/tags\/release(?:[/-])[A-Za-z0-9][A-Za-z0-9._/-]*$/;
const REVIEWED_TARGET_FIELDS = [
  ...PRIVATE_TARGET_VARIABLES,
  'publicKeySha256',
  'fingerprint'
];

function fail(message) {
  throw new Error('[MT] private artifact release ' + message);
}

function assertExactFields(value, fields, label) {
  if(!value || typeof value !== 'object' || Array.isArray(value)) {
    fail(`${label} is not an object`);
  }

  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if(JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} fields are incomplete or unexpected`);
  }
}

function assertString(value, label) {
  if(typeof value !== 'string' || !value) {
    fail(`${label} is missing`);
  }
}

function assertCommitId(value, label) {
  if(typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) {
    fail(`${label} is not a full commit id`);
  }
}

function sha256File(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}

function gitCommit(rootDirectory) {
  try {
    return execFileSync('git', ['rev-parse', '--verify', 'HEAD'], {
      cwd: rootDirectory,
      encoding: 'utf8'
    }).trim();
  } catch(cause) {
    throw new Error('[MT] private artifact release cannot determine source commit', {cause});
  }
}

function gitFile(rootDirectory, gitRef, filePath) {
  try {
    return execFileSync('git', ['show', `${gitRef}:${filePath}`], {
      cwd: rootDirectory,
      encoding: 'utf8'
    });
  } catch(cause) {
    throw new Error(`[MT] private artifact release cannot read ${filePath} from ${gitRef}`, {cause});
  }
}

function validateReviewedReleaseRefs(value) {
  if(!Array.isArray(value)) {
    fail('reviewed release ref list is not an array');
  }

  for(const entry of value) {
    assertExactFields(entry, ['ref', 'commit'], 'reviewed release ref');
    assertString(entry.ref, 'reviewed release ref name');
    assertCommitId(entry.commit, 'reviewed release ref commit');
    if(!REVIEWED_RELEASE_REF_PATTERN.test(entry.ref)) {
      fail('reviewed release ref must be a release tag');
    }
  }
  return value;
}

export function loadReviewedReleaseRefs({
  rootDirectory = ROOT_DIRECTORY,
  gitRef = 'refs/remotes/origin/master'
} = {}) {
  let reviewed;
  try {
    reviewed = JSON.parse(gitFile(rootDirectory, gitRef, REVIEWED_RELEASE_REFS));
  } catch(cause) {
    if(cause instanceof Error && cause.message.startsWith('[MT] private artifact release cannot read')) {
      throw cause;
    }
    throw new Error('[MT] private artifact release reviewed ref list is invalid', {cause});
  }
  assertExactFields(reviewed, ['releaseRefs'], 'reviewed release ref list');
  return validateReviewedReleaseRefs(reviewed.releaseRefs);
}

export function assertPublicationRef(ref, commit, reviewedReleaseRefs = []) {
  assertString(ref, 'publication ref');
  assertCommitId(commit, 'publication ref commit');

  if(ref === MASTER_REF) {
    return {ref, commit};
  }
  if(!REVIEWED_RELEASE_REF_PATTERN.test(ref)) {
    fail('publication ref must be refs/heads/master or an explicitly reviewed release ref');
  }

  const reviewed = validateReviewedReleaseRefs(reviewedReleaseRefs)
  .find((entry) => entry.ref === ref);
  if(!reviewed) {
    fail('publication ref is not explicitly reviewed');
  }
  if(reviewed.commit !== commit) {
    fail('publication ref commit does not match the reviewed release ref');
  }
  return {ref, commit};
}

export function validatePublicationRef({
  rootDirectory = ROOT_DIRECTORY,
  environment = process.env,
  reviewedReleaseRefs
} = {}) {
  const ref = environment.PRIVATE_ARTIFACT_REF || environment.GITHUB_REF;
  const commit = environment.PRIVATE_ARTIFACT_COMMIT || environment.GITHUB_SHA;
  assertString(ref, 'publication ref');
  assertCommitId(commit, 'publication ref commit');
  const reviewed = reviewedReleaseRefs ?? (
    ref !== MASTER_REF && REVIEWED_RELEASE_REF_PATTERN.test(ref)
      ? loadReviewedReleaseRefs({rootDirectory})
      : []
  );
  const result = assertPublicationRef(ref, commit, reviewed);
  console.log(`[private-artifact] publicationRef=${result.ref}`);
  console.log(`[private-artifact] publicationCommit=${result.commit}`);
  return result;
}

function targetFromEnvironment(environment) {
  try {
    return resolveMtprotoTarget(environment);
  } catch(cause) {
    throw new Error('[MT] private artifact release target validation failed', {cause});
  }
}

export function loadReviewedPrivateTarget({
  rootDirectory = ROOT_DIRECTORY,
  attestationPath = resolve(rootDirectory, REVIEWED_PRIVATE_TARGET)
} = {}) {
  if(!existsSync(attestationPath) || !statSync(attestationPath).isFile()) {
    fail('reviewed target attestation is missing');
  }

  let reviewed;
  try {
    reviewed = JSON.parse(readFileSync(attestationPath, 'utf8'));
  } catch(cause) {
    throw new Error('[MT] private artifact release reviewed target attestation is invalid', {cause});
  }
  assertExactFields(reviewed, REVIEWED_TARGET_FIELDS, 'reviewed target attestation');

  if(reviewed.MTPROTO_TARGET_MODE !== 'private') {
    fail('reviewed target mode is not private');
  }
  assertString(reviewed.MTPROTO_PRIVATE_ENDPOINT, 'reviewed target endpoint');
  assertString(reviewed.MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE, 'reviewed target key file');
  if(!/^[0-9a-f]{64}$/.test(reviewed.publicKeySha256)) {
    fail('reviewed target public-key digest is invalid');
  }
  if(!/^[0-9a-f]{16}$/.test(reviewed.fingerprint)) {
    fail('reviewed target fingerprint is invalid');
  }

  if(isAbsolute(reviewed.MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE)) {
    fail('reviewed target key file must be repository-relative');
  }
  const keyPath = resolve(rootDirectory, reviewed.MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE);
  const keyRelativePath = relative(rootDirectory, keyPath);
  if(!keyRelativePath || keyRelativePath === '..' || keyRelativePath.startsWith('../') || isAbsolute(keyRelativePath)) {
    fail('reviewed target key file must stay inside the repository');
  }
  if(!existsSync(keyPath) || !statSync(keyPath).isFile()) {
    fail('reviewed target public-key file is missing');
  }
  if(sha256File(keyPath) !== reviewed.publicKeySha256) {
    fail('reviewed target public-key file digest does not match the attestation');
  }

  const target = targetFromEnvironment({
    MTPROTO_TARGET_MODE: reviewed.MTPROTO_TARGET_MODE,
    MTPROTO_PRIVATE_ENDPOINT: reviewed.MTPROTO_PRIVATE_ENDPOINT,
    MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath
  });
  if(target.mode !== 'private' || target.endpoint !== reviewed.MTPROTO_PRIVATE_ENDPOINT ||
    target.fingerprint !== reviewed.fingerprint) {
    fail('reviewed target does not match the validated endpoint and public key');
  }

  return {reviewed, target, keyPath};
}

export function assertReviewedEnvironment(reviewed, environment = process.env) {
  const unexpected = Object.keys(environment)
  .filter((name) => name.startsWith('MTPROTO_PRIVATE_'))
  .filter((name) => !PRIVATE_TARGET_VARIABLES.includes(name));
  if(unexpected.length) {
    fail(`unrecognized target variables: ${unexpected.join(',')}`);
  }

  for(const name of PRIVATE_TARGET_VARIABLES) {
    if(environment[name] !== reviewed[name]) {
      fail(`${name} does not match the reviewed target attestation`);
    }
  }
}

function assertCommit(expectedCommit, rootDirectory) {
  const currentCommit = gitCommit(rootDirectory);
  const commit = expectedCommit || currentCommit;
  if(!/^[0-9a-f]{40}$/.test(commit)) {
    fail('source commit is not a full commit id');
  }
  if(currentCommit !== commit) {
    fail('checked-out source commit does not match the publication commit');
  }
  return commit;
}

function writeGithubOutputs(values) {
  if(!process.env.GITHUB_OUTPUT) return;
  for(const [name, value] of Object.entries(values)) {
    appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
  }
}

function logTarget(target, commit, manifest) {
  console.log(`[private-artifact] variables=${PRIVATE_TARGET_VARIABLES.join(',')}`);
  console.log(`[private-artifact] endpoint=${target.endpoint}`);
  console.log(`[private-artifact] keyFingerprint=${target.fingerprint}`);
  if(commit) console.log(`[private-artifact] sourceCommit=${commit}`);
  if(manifest) console.log(`[private-artifact] artifactDigest=${manifest.artifactDigest}`);
}

export function verifyPrivateArtifactRelease({
  directory,
  expectedCommit,
  environment = process.env,
  rootDirectory = ROOT_DIRECTORY,
  attestationPath,
  reviewedReleaseRefs
}) {
  if(typeof directory !== 'string' || !directory) {
    fail('artifact directory is missing');
  }

  const publication = validatePublicationRef({rootDirectory, environment, reviewedReleaseRefs});
  const {reviewed, target} = loadReviewedPrivateTarget({rootDirectory, attestationPath});
  assertReviewedEnvironment(reviewed, environment);
  const commit = assertCommit(expectedCommit || publication.commit, rootDirectory);
  if(commit !== publication.commit) {
    fail('publication commit does not match the reviewed publication ref');
  }
  const manifest = verifyPrivateArtifactManifest(directory, target);
  verifyPrivateArtifactCsp(directory, target.endpoint);
  if(manifest.sourceCommit !== commit) {
    fail('manifest source commit does not match the publication commit');
  }

  logTarget(target, commit, manifest);
  const artifactDigestHex = manifest.artifactDigest.slice('sha256:'.length);
  writeGithubOutputs({
    artifact_digest: manifest.artifactDigest,
    artifact_digest_hex: artifactDigestHex,
    key_fingerprint: target.fingerprint,
    source_commit: commit,
    publication_ref: publication.ref
  });
  return {manifest, target, commit};
}

function option(args, name, fallback) {
  const index = args.indexOf(name);
  if(index === -1) return fallback;
  const value = args[index + 1];
  if(!value || value.startsWith('--')) fail(`${name} requires a value`);
  return value;
}

function main() {
  const [command = 'verify', ...args] = process.argv.slice(2);
  if(command === 'validate-ref') {
    validatePublicationRef();
    return;
  }
  const {reviewed, target} = loadReviewedPrivateTarget();
  assertReviewedEnvironment(reviewed);

  if(command === 'validate-target') {
    logTarget(target);
    return;
  }
  if(command !== 'verify') {
    fail(`unknown command ${command}`);
  }

  verifyPrivateArtifactRelease({
    directory: option(args, '--dist', 'dist-private'),
    expectedCommit: option(args, '--commit', process.env.PRIVATE_ARTIFACT_COMMIT)
  });
}

const invokedScript = process.argv[1] && resolve(process.argv[1]);
if(invokedScript === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch(error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
