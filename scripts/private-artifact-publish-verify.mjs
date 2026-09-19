import {createHash} from 'node:crypto';
import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync
} from 'node:fs';
import {relative, resolve, sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {resolveMtprotoTarget} from './mtproto-target.mjs';

const MANIFEST = 'mtproto-target.json';
const SNAPSHOT = 'snapshot.json';
const TARGET_ATTESTATION = 'ci/private-mtproto-target.json';
const TARGET_FIELDS = [
  'MTPROTO_TARGET_MODE',
  'MTPROTO_PRIVATE_ENDPOINT',
  'MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE',
  'publicKeySha256',
  'fingerprint'
];
const SNAPSHOT_FIELDS = [
  'sourceRef',
  'sourceCommit',
  'reviewedWorkflowCommit',
  'targetMode',
  'endpoint',
  'keyPath',
  'publicKeySha256',
  'fingerprint'
];
const RELEASE_REF_PATTERN = /^refs\/tags\/release(?:[/-])[A-Za-z0-9][A-Za-z0-9._/-]*$/;

function fail(message) {
  throw new Error('[MT] private artifact publisher ' + message);
}

function exactFields(value, fields, label) {
  if(!value || typeof value !== 'object' || Array.isArray(value) ||
    JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields are incomplete or unexpected`);
  }
}

function stringValue(value, label) {
  if(typeof value !== 'string' || !value) fail(`${label} is missing`);
  return value;
}

function commitValue(value, label) {
  if(typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) {
    fail(`${label} is not a full commit id`);
  }
  return value;
}

function readJson(path, label) {
  if(!existsSync(path) || !statSync(path).isFile()) fail(`${label} is missing`);
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch(cause) {
    throw new Error(`[MT] private artifact publisher ${label} is invalid`, {cause});
  }
}

function sha256File(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function artifactFiles(directory) {
  const files = [];
  const visit = (current) => {
    for(const entry of readdirSync(current, {withFileTypes: true})) {
      const path = resolve(current, entry.name);
      if(entry.isDirectory()) {
        visit(path);
      } else if(entry.isFile()) {
        files.push(path);
      } else {
        fail('artifact contains a non-regular output entry');
      }
    }
  };
  if(!existsSync(directory) || !statSync(directory).isDirectory()) {
    fail('artifact directory is missing');
  }
  visit(resolve(directory));
  return files.sort((left, right) => relative(directory, left).localeCompare(relative(directory, right)));
}

function digestArtifact(directory) {
  const hash = createHash('sha256');
  for(const path of artifactFiles(directory)) {
    const relativePath = relative(directory, path).split(sep).join('/');
    if(relativePath === MANIFEST) continue;
    const contents = readFileSync(path);
    hash.update(relativePath + '\0' + contents.length + '\0');
    hash.update(contents);
    hash.update('\0');
  }
  return hash.digest('hex');
}

function privateCsp(endpoint) {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "media-src 'self' blob:",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    `connect-src 'self' ${endpoint}`
  ].join('; ') + ';';
}

function option(args, name) {
  const index = args.indexOf(name);
  if(index === -1 || !args[index + 1] || args[index + 1].startsWith('--')) {
    fail(`${name} requires a value`);
  }
  return args[index + 1];
}

export function verifyPublishedArtifact({directory, snapshotDirectory, sourceRef, sourceCommit, artifactDigest}) {
  stringValue(sourceRef, 'publication ref');
  if(sourceRef !== 'refs/heads/master' && !RELEASE_REF_PATTERN.test(sourceRef)) {
    fail('publication ref is not allowed');
  }
  commitValue(sourceCommit, 'publication commit');
  if(!/^[0-9a-f]{64}$/.test(artifactDigest)) fail('artifact digest is invalid');

  const snapshot = readJson(resolve(snapshotDirectory, SNAPSHOT), 'target snapshot');
  exactFields(snapshot, SNAPSHOT_FIELDS, 'target snapshot');
  if(snapshot.sourceRef !== sourceRef || snapshot.sourceCommit !== sourceCommit) {
    fail('target snapshot does not match the publication inputs');
  }
  commitValue(snapshot.reviewedWorkflowCommit, 'reviewed workflow commit');

  const reviewed = readJson(resolve(snapshotDirectory, TARGET_ATTESTATION), 'target attestation');
  exactFields(reviewed, TARGET_FIELDS, 'target attestation');
  if(reviewed.MTPROTO_TARGET_MODE !== 'private' || snapshot.targetMode !== 'private' ||
    reviewed.MTPROTO_PRIVATE_ENDPOINT !== snapshot.endpoint ||
    reviewed.MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE !== snapshot.keyPath ||
    reviewed.publicKeySha256 !== snapshot.publicKeySha256 ||
    reviewed.fingerprint !== snapshot.fingerprint) {
    fail('target snapshot metadata does not match its attestation');
  }

  const keyPath = resolve(snapshotDirectory, reviewed.MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE);
  const keyRelativePath = relative(snapshotDirectory, keyPath);
  if(!keyRelativePath || keyRelativePath === '..' || keyRelativePath.startsWith('../')) {
    fail('target public key must stay inside the snapshot');
  }
  if(!existsSync(keyPath) || !statSync(keyPath).isFile()) fail('target public key is missing');
  if(sha256File(keyPath) !== reviewed.publicKeySha256) {
    fail('target public-key digest does not match the attestation');
  }
  const target = resolveMtprotoTarget({
    MTPROTO_TARGET_MODE: reviewed.MTPROTO_TARGET_MODE,
    MTPROTO_PRIVATE_ENDPOINT: reviewed.MTPROTO_PRIVATE_ENDPOINT,
    MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath
  });
  if(target.endpoint !== reviewed.MTPROTO_PRIVATE_ENDPOINT || target.fingerprint !== reviewed.fingerprint) {
    fail('target attestation does not match the validated key');
  }

  const manifest = readJson(resolve(directory, MANIFEST), 'artifact manifest');
  exactFields(manifest, ['mode', 'endpoint', 'fingerprint', 'sourceCommit', 'artifactDigest'], 'artifact manifest');
  if(manifest.mode !== 'private' || manifest.endpoint !== target.endpoint ||
    manifest.fingerprint !== target.fingerprint || manifest.sourceCommit !== sourceCommit ||
    manifest.artifactDigest !== `sha256:${artifactDigest}`) {
    fail('artifact manifest does not match the immutable publication inputs');
  }
  if(digestArtifact(directory) !== artifactDigest) {
    fail('downloaded artifact digest does not match the verified build output');
  }

  const index = readFileSync(resolve(directory, 'index.html'), 'utf8');
  if(!index.includes(privateCsp(target.endpoint))) {
    fail('downloaded artifact CSP does not match the immutable target');
  }
  return {manifest, target, sourceRef, sourceCommit, artifactDigest};
}

const invokedScript = process.argv[1] && resolve(process.argv[1]);
if(invokedScript === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    verifyPublishedArtifact({
      directory: option(args, '--dist'),
      snapshotDirectory: option(args, '--snapshot'),
      sourceRef: option(args, '--ref'),
      sourceCommit: option(args, '--commit'),
      artifactDigest: option(args, '--digest')
    });
    console.log('[private-artifact] downloaded artifact re-verification passed');
  } catch(error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
