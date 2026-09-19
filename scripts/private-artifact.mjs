import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
  writeFileSync
} from 'node:fs';
import {relative, resolve, sep} from 'node:path';
import {readHeadContentSecurityPolicies} from './private-artifact-csp.mjs';

export const PRIVATE_ARTIFACT_MANIFEST = 'mtproto-target.json';

const PRIVATE_ROUTE_LOCK = {
  mode: 'private',
  transport: 'websocket',
  dcIds: [1, 2, 3, 4, 5],
  connectionTypes: ['client', 'upload', 'download']
};

const TRUSTED_MT_PROTO_FINGERPRINTS = [
  'c3b42b026ce86b21',
  '0bc35f3509f7b7a5',
  '15ae5fa8b5529542',
  'aeae98e13cd7f94f',
  '5a181b2235057d98',
  'b25898df208d2603',
  'd09d1d85de64fd85'
];

const TRUSTED_MT_PROTO_MODULI = [
  'c150023e2f70db7985ded064759cfecf0af328e69a41daf4d6f01b538135a6f91f8f8b2a0ec9ba9720ce352efcf6c5680ffc424bd634864902de0b4bd6d49f4e580230e3ae97d95c8b19442b3c0a10d8f5633fecedd6926a7f6dab0ddb7d457f9ea81b8465fcd6fffeed114011df91c059caedaf97625f6c96ecc74725556934ef781d866b34f011fce4d835a090196e9a5f0e4449af7eb697ddb9076494ca5f81104a305b6dd27665722c46b60e5df680fb16b210607ef217652e60236c255f6a28315f4083a96791d7214bf64c1df4fd0db1944fb26a2a57031b32eee64ad15a8ba68885cde74a5bfc920f6abf59ba5c75506373e7130f9042da922179251f',
  'aeec36c8ffc109cb099624685b97815415657bd76d8c9c3e398103d7ad16c9bba6f525ed0412d7ae2c2de2b44e77d72cbf4b7438709a4e646a05c43427c7f184debf72947519680e651500890c6832796dd11f772c25ff8f576755afe055b0a3752c696eb7d8da0d8be1faf38c9bdd97ce0a77d3916230c4032167100edd0f9e7a3a9b602d04367b689536af0d64b613ccba7962939d3b57682beb6dae5b608130b2e52aca78ba023cf6ce806b1dc49c72cf928a7199d22e3d7ac84e47bc9427d0236945d10dbd15177bab413fbf0edfda09f014c7a7da088dde9759702ca760af2b8e4e97cc055c617bd74c3d97008635b98dc4d621b4891da9fb0473047927',
  'bdf2c77d81f6afd47bd30f29ac76e55adfe70e487e5e48297e5a9055c9c07d2b93b4ed3994d3eca5098bf18d978d54f8b7c713eb10247607e69af9ef44f38e28f8b439f257a11572945cc0406fe3f37bb92b79112db69eedf2dc71584a661638ea5becb9e23585074b80d57d9f5710dd30d2da940e0ada2f1b878397dc1a72b5ce2531b6f7dd158e09c828d03450ca0ff8a174deacebcaa22dde84ef66ad370f259d18af806638012da0ca4a70baa83d9c158f3552bc9158e69bf332a45809e1c36905a5caa12348dd57941a482131be7b2355a5f4635374f3bd3ddf5ff925bf4809ee27c1e67d9120c5fe08a9de458b1b4a3c5d0a428437f2beca81f4e2d5ff',
  'b3f762b739be98f343eb1921cf0148cfa27ff7af02b6471213fed9daa0098976e667750324f1abcea4c31e43b7d11f1579133f2b3d9fe27474e462058884e5e1b123be9cbbc6a443b2925c08520e7325e6f1a6d50e117eb61ea49d2534c8bb4d2ae4153fabe832b9edf4c5755fdd8b19940b81d1d96cf433d19e6a22968a85dc80f0312f596bd2530c1cfb28b5fe019ac9bc25cd9c2a5d8a0f3a1c0c79bcca524d315b5e21b5c26b46babe3d75d06d1cd33329ec782a0f22891ed1db42a1d6c0dea431428bc4d7aabdcf3e0eb6fda4e23eb7733e7727e9a1915580796c55188d2596d2665ad1182ba7abf15aaa5a8b779ea996317a20ae044b820bff35b6e8a1',
  'be6a71558ee577ff03023cfa17aab4e6c86383cff8a7ad38edb9fafe6f323f2d5106cbc8cafb83b869cffd1ccf121cd743d509e589e68765c96601e813dc5b9dfc4be415c7a6526132d0035ca33d6d6075d4f535122a1cdfe017041f1088d1419f65c8e5490ee613e16dbf662698c0f54870f0475fa893fc41eb55b08ff1ac211bc045ded31be27d12c96d8d3cfc6a7ae8aa50bf2ee0f30ed507cc2581e3dec56de94f5dc0a7abee0be990b893f2887bd2c6310a1e0a9e3e38bd34fded2541508dc102a9c9b4c95effd9dd2dfe96c29be647d6c69d66ca500843cfaed6e440196f1dbe0e2e22163c61ca48c79116fa77216726749a976a1c4b0944b5121e8c01',
  'c8c11d635691fac091dd9489aedced2932aa8a0bcefef05fa800892d9b52ed03200865c9e97211cb2ee6c7ae96d3fb0e15aeffd66019b44a08a240cfdd2868a85e1f54d6fa5deaa041f6941ddf302690d61dc476385c2fa655142353cb4e4b59f6e5b6584db76fe8b1370263246c010c93d011014113ebdf987d093f9d37c2be48352d69a1683f8f6e6c2167983c761e3ab169fde5daaa12123fa1beab621e4da5935e9c198f82f35eae583a99386d8110ea6bd1abb0f568759f62694419ea5f69847c43462abef858b4cb5edc84e7b9226cd7bd7e183aa974a712c079dde85b9dc063b8a5c08e8f859c0ee5dcd824c7807f20153361a7f63cfd2a433a1be7f5',
  'e8bb3305c0b52c6cf2afdf7637313489e63e05268e5badb601af417786472e5f93b85438968e20e6729a301c0afc121bf7151f834436f7fda680847a66bf64accec78ee21c0b316f0edafe2f41908da7bd1f4a5107638eeb67040ace472a14f90d9f7c2b7def99688ba3073adb5750bb02964902a359fe745d8170e36876d4fd8a5d41b2a76cbff9a13267eb9580b2d06d10357448d20d9da2191cb5d8c93982961cdfdeda629e37f1fb09a0722027696032fe61ed663db7a37f6f263d370f69db53a0dc0a1748bdaaff6209d5645485e6e001d1953255757e4b8e42813347b11da6ab500fd0ace7e6dfa3736199ccaf9397ed0745a427dcfa6cd67bcb1acff3'
];

const PRIVATE_EXECUTABLE_EXTENSIONS = new Set(['.js', '.mjs']);
const OFFICIAL_MT_PROTO_ROUTE = /(?:kws[1-5](?:-1)?|pluto(?:-1)?|venus(?:-1)?|aurora(?:-1)?|vesta(?:-1)?|flora(?:-1)?)\.web\.telegram\.org(?:[/:?#]|$)|web\.telegram\.org\/(?:apiw(?:s|_test1|1)?)(?:[/:?#]|$)/i;
const OFFICIAL_MT_PROTO_DYNAMIC_ROUTE = /\$\{[^}]+\}[^`]*\.web\.telegram\.org|['"`]\.?web\.telegram\.org\/?['"`]\s*\+|\+\s*['"`]\.?web\.telegram\.org\/?['"`]/i;
const OFFICIAL_MT_PROTO_IP = /\b(?:149\.154|149\.155|91\.108)\.\d{1,3}\.\d{1,3}\b/;
const HTTP_MTPROTO_ROUTE = /https?:\/\/[^\s"'`<>]+\/apiw(?:_test1|1)(?:[/?#"'`<>\s]|$)/i;
const PRIVATE_WSS_URL = /wss:\/\/[A-Za-z0-9._:[\]-]+(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?/gi;

function invalidArtifact(message) {
  throw new Error('[MT] private artifact ' + message);
}

function artifactFiles(directory) {
  const files = [];
  const visit = (current) => {
    for(const entry of readdirSync(current, {withFileTypes: true})) {
      const file = resolve(current, entry.name);
      if(entry.isDirectory()) {
        visit(file);
      } else if(entry.isFile()) {
        files.push(file);
      } else {
        invalidArtifact('contains a non-regular output entry');
      }
    }
  };

  if(!existsSync(directory) || !statSync(directory).isDirectory()) {
    invalidArtifact('directory is missing');
  }
  visit(resolve(directory));
  return files.sort((left, right) => relative(directory, left).localeCompare(relative(directory, right)));
}

function digestArtifact(directory) {
  const hash = createHash('sha256');
  for(const file of artifactFiles(directory)) {
    const relativePath = relative(directory, file).split(sep).join('/');
    if(relativePath === PRIVATE_ARTIFACT_MANIFEST) continue;
    const contents = readFileSync(file);
    hash.update(relativePath + '\0' + contents.length + '\0');
    hash.update(contents);
    hash.update('\0');
  }
  return 'sha256:' + hash.digest('hex');
}

function normalizedText(contents) {
  return contents.toString('utf8');
}

function allPrivateWssUrls(text) {
  return [...text.matchAll(PRIVATE_WSS_URL)].map((match) => match[0].replace(/[),.;}]+$/, ''));
}

function assertPrivateEndpoint(endpoint, label) {
  if(typeof endpoint !== 'string' || !/^wss:\/\/[^/]/i.test(endpoint)) {
    invalidArtifact(`${label} is not normalized`);
  }

  let parsed;
  try {
    parsed = new URL(endpoint);
  } catch{
    invalidArtifact(`${label} is not normalized`);
  }

  const hostname = parsed.hostname.toLowerCase().replace(/\.+$/, '');
  parsed.hostname = hostname;
  if(parsed.protocol !== 'wss:' || !hostname || parsed.username || parsed.password ||
    parsed.search || parsed.hash || hostname === 'telegram.org' || hostname.endsWith('.telegram.org') ||
    parsed.href !== endpoint) {
    invalidArtifact(`${label} is not normalized`);
  }
}

function assertManifestShape(manifest) {
  if(!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    invalidArtifact('manifest is not an object');
  }

  const fields = ['mode', 'endpoint', 'fingerprint', 'sourceCommit', 'artifactDigest'];
  if(JSON.stringify(Object.keys(manifest).sort()) !== JSON.stringify(fields.sort())) {
    invalidArtifact('manifest fields are incomplete or unexpected');
  }
  if(manifest.mode !== 'private') {
    invalidArtifact('manifest mode is not private');
  }
  assertPrivateEndpoint(manifest.endpoint, 'manifest endpoint');
  if(typeof manifest.fingerprint !== 'string' || !/^[0-9a-f]{16}$/.test(manifest.fingerprint)) {
    invalidArtifact('manifest fingerprint is invalid');
  }
  if(typeof manifest.sourceCommit !== 'string' || !/^[0-9a-f]{40}$/.test(manifest.sourceCommit)) {
    invalidArtifact('manifest source commit is invalid');
  }
  if(typeof manifest.artifactDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(manifest.artifactDigest)) {
    invalidArtifact('manifest artifact digest is invalid');
  }
}

export function privateContentSecurityPolicy(endpoint) {
  assertPrivateEndpoint(endpoint, 'CSP endpoint');

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

export function verifyPrivateArtifactCsp(directory, endpoint) {
  const indexPath = resolve(directory, 'index.html');
  if(!existsSync(indexPath)) {
    invalidArtifact('index document is missing');
  }

  const expectedPolicy = privateContentSecurityPolicy(endpoint);
  const policies = readHeadContentSecurityPolicies(readFileSync(indexPath, 'utf8'));
  if(!policies.includes(expectedPolicy)) {
    invalidArtifact('index document CSP does not match the configured endpoint');
  }

  const connectSources = policies
  .flatMap((policy) => [...policy.matchAll(/connect-src\s+([^;]+)/gi)])
  .flatMap((match) => match[1].trim().split(/\s+/))
  .map((source) => source.replace(/^['"]|['"]$/g, ''))
  .filter((source) => source.startsWith('wss://'));
  if(connectSources.some((source) => source !== endpoint)) {
    invalidArtifact('index document CSP contains an unexpected WSS endpoint');
  }
}

export function auditPrivateArtifact(directory, target) {
  if(!target || target.mode !== 'private' || typeof target.endpoint !== 'string' ||
    !/^[0-9a-f]{16}$/.test(target.fingerprint)) {
    invalidArtifact('target metadata is missing');
  }
  assertPrivateEndpoint(target.endpoint, 'target endpoint');

  const files = artifactFiles(directory);
  const executableFiles = files.filter((file) => PRIVATE_EXECUTABLE_EXTENSIONS.has(file.slice(file.lastIndexOf('.'))));
  if(!executableFiles.length) {
    invalidArtifact('contains no executable client or worker artifact');
  }

  const privateUrls = new Set();
  for(const file of executableFiles) {
    const text = normalizedText(readFileSync(file));
    const relativePath = relative(directory, file).split(sep).join('/');
    if(OFFICIAL_MT_PROTO_ROUTE.test(text) || OFFICIAL_MT_PROTO_DYNAMIC_ROUTE.test(text)) {
      invalidArtifact(`contains an official Telegram MTProto route in ${relativePath}`);
    }
    if(OFFICIAL_MT_PROTO_IP.test(text)) {
      invalidArtifact(`contains an official Telegram MTProto IP route in ${relativePath}`);
    }
    if(HTTP_MTPROTO_ROUTE.test(text)) {
      invalidArtifact(`contains an HTTP MTProto transport in ${relativePath}`);
    }

    const lower = text.toLowerCase();
    for(const fingerprint of TRUSTED_MT_PROTO_FINGERPRINTS) {
      if(lower.includes(fingerprint)) {
        invalidArtifact(`contains a trusted Telegram RSA fingerprint in ${relativePath}`);
      }
    }
    for(const modulus of TRUSTED_MT_PROTO_MODULI) {
      if(lower.includes(modulus)) {
        invalidArtifact(`contains a trusted Telegram RSA public key in ${relativePath}`);
      }
    }
    for(const endpoint of allPrivateWssUrls(text)) {
      privateUrls.add(endpoint);
    }
  }

  if(!privateUrls.has(target.endpoint)) {
    invalidArtifact('does not contain its configured WSS endpoint');
  }
  const unexpected = [...privateUrls].filter((endpoint) => endpoint !== target.endpoint);
  if(unexpected.length) {
    invalidArtifact('contains a second private MTProto target');
  }
  if(lowercaseFiles(files, directory).includes(target.fingerprint.toLowerCase()) === false) {
    invalidArtifact('does not contain its configured RSA fingerprint');
  }
}

function lowercaseFiles(files, directory) {
  return files
  .filter((file) => PRIVATE_EXECUTABLE_EXTENSIONS.has(file.slice(file.lastIndexOf('.'))))
  .map((file) => normalizedText(readFileSync(file)).toLowerCase())
  .join('\n');
}

function sourceCommit(rootDirectory) {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], {cwd: rootDirectory, encoding: 'utf8'}).trim();
  } catch(cause) {
    throw new Error('[MT] unable to determine private artifact source commit', {cause});
  }
}

export function verifyPrivateArtifactManifest(directory, expectedTarget) {
  const manifestPath = resolve(directory, PRIVATE_ARTIFACT_MANIFEST);
  if(!existsSync(manifestPath)) {
    invalidArtifact('manifest is missing');
  }

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  } catch(cause) {
    throw new Error('[MT] private artifact manifest is invalid', {cause});
  }
  assertManifestShape(manifest);

  if(expectedTarget && (expectedTarget.mode !== manifest.mode ||
    expectedTarget.endpoint !== manifest.endpoint || expectedTarget.fingerprint !== manifest.fingerprint)) {
    invalidArtifact('manifest does not match the validated target');
  }
  const digest = digestArtifact(directory);
  if(digest !== manifest.artifactDigest) {
    invalidArtifact('digest does not match the completed artifact');
  }

  auditPrivateArtifact(directory, {
    mode: 'private',
    endpoint: manifest.endpoint,
    fingerprint: manifest.fingerprint
  });
  return manifest;
}

export function writePrivateArtifactManifest(directory, target, rootDirectory) {
  if(!target || target.mode !== 'private' || !target.routeLock ||
    target.routeLock.mode !== PRIVATE_ROUTE_LOCK.mode || target.routeLock.endpoint !== target.endpoint ||
    target.routeLock.transport !== PRIVATE_ROUTE_LOCK.transport ||
    JSON.stringify(target.routeLock.dcIds) !== JSON.stringify(PRIVATE_ROUTE_LOCK.dcIds) ||
    JSON.stringify(target.routeLock.connectionTypes) !== JSON.stringify(PRIVATE_ROUTE_LOCK.connectionTypes)) {
    invalidArtifact('target and route-lock metadata are inconsistent');
  }

  auditPrivateArtifact(directory, target);
  const manifest = {
    mode: 'private',
    endpoint: target.endpoint,
    fingerprint: target.fingerprint,
    sourceCommit: sourceCommit(rootDirectory),
    artifactDigest: digestArtifact(directory)
  };
  assertManifestShape(manifest);
  writeFileSync(resolve(directory, PRIVATE_ARTIFACT_MANIFEST), JSON.stringify(manifest, null, 2) + '\n');
  verifyPrivateArtifactManifest(directory, target);
  return manifest;
}

export function createPrivateArtifactPlugin(rootDirectory, target) {
  return {
    name: 'private-mtproto-artifact',
    apply: 'build',
    transformIndexHtml(html) {
      return {
        html,
        tags: [{
          tag: 'meta',
          attrs: {
            'http-equiv': 'Content-Security-Policy',
            content: privateContentSecurityPolicy(target.endpoint)
          },
          injectTo: 'head-prepend'
        }]
      };
    },
    writeBundle(options) {
      const directory = resolve(rootDirectory, options.dir || 'dist');
      writePrivateArtifactManifest(directory, target, rootDirectory);
    }
  };
}
