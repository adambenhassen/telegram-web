import {createHash, createPublicKey} from 'node:crypto';
import {closeSync, constants, fstatSync, openSync, readSync} from 'node:fs';

const PRIVATE_ENDPOINT = 'MTPROTO_PRIVATE_ENDPOINT';
const PRIVATE_KEY_FILE = 'MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE';
const PRIVATE_FIELDS = new Set([PRIVATE_ENDPOINT, PRIVATE_KEY_FILE]);
const MAX_PUBLIC_KEY_FILE_BYTES = 16 * 1024;

function decodeBase64Url(value) {
  return Buffer.from(value.replaceAll('-', '+').replaceAll('_', '/'), 'base64');
}

function serializeTlBytes(bytes) {
  const length = bytes.length;
  const header = length < 254 ?
    Buffer.from([length]) :
    Buffer.from([254, length & 0xff, length >> 8 & 0xff, length >> 16 & 0xff]);
  const padding = Buffer.alloc((4 - (header.length + length) % 4) % 4);
  return Buffer.concat([header, bytes, padding]);
}

function normalizeEndpoint(value) {
  if(!/^wss:\/\/[^/]/i.test(value)) {
    throw new Error(`${PRIVATE_ENDPOINT} must contain a host`);
  }

  let endpoint;
  try {
    endpoint = new URL(value);
  } catch{
    throw new Error(`${PRIVATE_ENDPOINT} must be an absolute wss URL`);
  }

  if(endpoint.protocol !== 'wss:') {
    throw new Error(`${PRIVATE_ENDPOINT} must use wss`);
  }
  if(endpoint.username || endpoint.password) {
    throw new Error(`${PRIVATE_ENDPOINT} must not contain credentials`);
  }
  if(value.includes('?') || endpoint.search) {
    throw new Error(`${PRIVATE_ENDPOINT} must not contain a query`);
  }
  if(value.includes('#') || endpoint.hash) {
    throw new Error(`${PRIVATE_ENDPOINT} must not contain a fragment`);
  }

  const hostname = endpoint.hostname.toLowerCase().replace(/\.+$/, '');
  if(!hostname) {
    throw new Error(`${PRIVATE_ENDPOINT} must contain a host`);
  }
  if(hostname === 'telegram.org' || hostname.endsWith('.telegram.org')) {
    throw new Error(`${PRIVATE_ENDPOINT} must not target telegram.org`);
  }

  endpoint.hostname = hostname;
  return endpoint.href;
}

function readPublicKey(filePath) {
  let contents;
  let descriptor;
  try {
    descriptor = openSync(filePath, constants.O_RDONLY | constants.O_NONBLOCK);
    const stats = fstatSync(descriptor);
    if(!stats.isFile() || stats.size > MAX_PUBLIC_KEY_FILE_BYTES) {
      throw new Error('Invalid private MTProto public key file');
    }

    const buffer = Buffer.alloc(MAX_PUBLIC_KEY_FILE_BYTES + 1);
    let length = 0;
    while(length < buffer.length) {
      const bytesRead = readSync(descriptor, buffer, length, buffer.length - length, null);
      if(!bytesRead) {
        break;
      }
      length += bytesRead;
    }
    if(length > MAX_PUBLIC_KEY_FILE_BYTES) {
      throw new Error('Invalid private MTProto public key file');
    }
    contents = buffer.subarray(0, length).toString('utf8');
  } catch{
    throw new Error('Unable to read private MTProto public key file');
  } finally {
    if(descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch{}
    }
  }

  if(/-----BEGIN [^-]*PRIVATE KEY-----/.test(contents)) {
    throw new Error('Private MTProto key file contains private key material');
  }

  const publicKey = contents.trim().replaceAll('\r\n', '\n');
  const match = publicKey.match(
    /^-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY)-----\n([A-Za-z0-9+/=\n]+)\n-----END \1-----$/
  );
  if(!match) {
    throw new Error('Private MTProto key file must contain exactly one public RSA key');
  }

  const payload = match[2].replaceAll('\n', '');
  const inputDer = Buffer.from(payload, 'base64');
  if(inputDer.toString('base64') !== payload) {
    throw new Error('Private MTProto key file must contain exactly one public RSA key');
  }

  let key;
  try {
    key = createPublicKey(publicKey);
  } catch(cause) {
    throw new Error('Private MTProto key file must contain exactly one public RSA key', {cause});
  }

  const keyType = match[1] === 'PUBLIC KEY' ? 'spki' : 'pkcs1';
  const canonicalDer = key.export({format: 'der', type: keyType});
  if(!inputDer.equals(canonicalDer)) {
    throw new Error('Private MTProto key file must contain exactly one public RSA key');
  }

  const jwk = key.export({format: 'jwk'});
  if(key.asymmetricKeyType !== 'rsa' || !jwk.n || !jwk.e) {
    throw new Error('Private MTProto key must be a 2048-bit RSA key with exponent 65537');
  }

  const modulus = decodeBase64Url(jwk.n);
  const exponent = decodeBase64Url(jwk.e);
  const modulusBits = modulus.length * 8 - Math.clz32(modulus[0]) + 24;
  const exponentValue = exponent.reduce((value, byte) => value * 256 + byte, 0);
  if(modulusBits !== 2048 || exponentValue !== 65537) {
    throw new Error('Private MTProto key must be a 2048-bit RSA key with exponent 65537');
  }

  const serializedKey = Buffer.concat([serializeTlBytes(modulus), serializeTlBytes(exponent)]);
  const digest = createHash('sha1').update(serializedKey).digest();
  const fingerprint = Buffer.from(digest.subarray(-8)).reverse().toString('hex');
  return {fingerprint, publicKey: key.export({format: 'pem', type: keyType}).toString()};
}

export function resolveMtprotoTarget(env) {
  const privateFieldNames = Object.keys(env).filter((name) => name.startsWith('MTPROTO_PRIVATE_'));
  const unknownField = privateFieldNames.find((name) => !PRIVATE_FIELDS.has(name));
  if(unknownField) {
    throw new Error(`Unrecognized private MTProto target field: ${unknownField}`);
  }

  const mode = env.MTPROTO_TARGET_MODE;
  if(mode === undefined && privateFieldNames.length === 0) {
    return {mode: 'telegram'};
  }
  if(mode !== 'private' && mode !== 'telegram') {
    throw new Error('MTPROTO_TARGET_MODE must be either telegram or private');
  }
  if(mode === 'telegram') {
    if(privateFieldNames.length) {
      throw new Error('Private MTProto target fields require MTPROTO_TARGET_MODE=private');
    }
    return {mode: 'telegram'};
  }

  const endpointValue = env[PRIVATE_ENDPOINT];
  const keyFileValue = env[PRIVATE_KEY_FILE];
  if(typeof endpointValue !== 'string' || !endpointValue.trim() ||
    typeof keyFileValue !== 'string' || !keyFileValue.trim()) {
    throw new Error(`Private mode requires non-empty ${PRIVATE_ENDPOINT} and ${PRIVATE_KEY_FILE}`);
  }

  const endpoint = normalizeEndpoint(endpointValue.trim());
  const {fingerprint, publicKey} = readPublicKey(keyFileValue.trim());
  return {mode: 'private', endpoint, fingerprint, publicKey};
}

export function assertRunnableMtprotoTarget(target) {
  if(target.mode === 'private') {
    throw new Error(
      `Private MTProto target validated: endpoint=${target.endpoint} fingerprint=${target.fingerprint}. ` +
      'Private routing is not implemented; no runnable artifact was emitted.'
    );
  }
}
