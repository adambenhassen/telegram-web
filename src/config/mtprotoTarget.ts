export type RSAPublicKeyHex = {
  modulus: string,
  exponent: string
};

export type MtprotoRouteLock = {
  readonly mode: 'private',
  readonly endpoint: string,
  readonly transport: 'websocket',
  readonly dcIds: readonly number[],
  readonly connectionTypes: readonly ('client' | 'upload' | 'download')[]
};

export type MtprotoTarget =
  | {
    readonly mode: 'telegram'
  }
  | {
    readonly mode: 'private',
    readonly endpoint: string,
    readonly fingerprint: string,
    readonly publicKey: string,
    readonly publicKeyHex: RSAPublicKeyHex,
    readonly routeLock: MtprotoRouteLock
  };

declare const __MTPROTO_TARGET__: MtprotoTarget | undefined;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function invalidTarget(message: string): never {
  throw new Error('[MT] embedded target metadata ' + message);
}

function rotateLeft(value: number, bits: number) {
  return (value << bits | value >>> (32 - bits)) >>> 0;
}

function sha1(bytes: Uint8Array) {
  const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLength);
  padded.set(bytes);
  padded[bytes.length] = 0x80;
  const view = new DataView(padded.buffer);
  const bitLength = bytes.length * 8;
  view.setUint32(paddedLength - 4, bitLength >>> 0);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000));

  let h0 = 0x67452301;
  let h1 = 0xefcdab89;
  let h2 = 0x98badcfe;
  let h3 = 0x10325476;
  let h4 = 0xc3d2e1f0;
  const words = new Uint32Array(80);

  for(let offset = 0; offset < padded.length; offset += 64) {
    for(let i = 0; i < 16; ++i) {
      words[i] = view.getUint32(offset + i * 4);
    }
    for(let i = 16; i < 80; ++i) {
      words[i] = rotateLeft(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
    }

    let a = h0;
    let b = h1;
    let c = h2;
    let d = h3;
    let e = h4;
    for(let i = 0; i < 80; ++i) {
      let f: number, k: number;
      if(i < 20) {
        f = b & c | ~b & d;
        k = 0x5a827999;
      } else if(i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if(i < 60) {
        f = b & c | b & d | c & d;
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }

      const next = (rotateLeft(a, 5) + f + e + k + words[i]) >>> 0;
      e = d;
      d = c;
      c = rotateLeft(b, 30);
      b = a;
      a = next;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
  }

  return [h0, h1, h2, h3, h4].map((word) => word.toString(16).padStart(8, '0')).join('');
}

function hexBytes(value: string) {
  const bytes = new Uint8Array(value.length / 2);
  for(let i = 0; i < bytes.length; ++i) {
    bytes[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function serializeTlBytes(value: string) {
  const bytes = hexBytes(value);
  const headerLength = bytes.length < 254 ? 1 : 4;
  const output = new Uint8Array(headerLength + bytes.length + (4 - (headerLength + bytes.length) % 4) % 4);
  if(headerLength === 1) {
    output[0] = bytes.length;
  } else {
    output[0] = 254;
    output[1] = bytes.length & 0xff;
    output[2] = bytes.length >> 8 & 0xff;
    output[3] = bytes.length >> 16 & 0xff;
  }
  output.set(bytes, headerLength);
  return output;
}

function deriveFingerprint(publicKeyHex: RSAPublicKeyHex) {
  const modulus = serializeTlBytes(publicKeyHex.modulus);
  const exponent = serializeTlBytes(publicKeyHex.exponent);
  const serialized = new Uint8Array(modulus.length + exponent.length);
  serialized.set(modulus);
  serialized.set(exponent, modulus.length);
  const digest = sha1(serialized);
  let fingerprint = '';
  for(let i = digest.length - 2; i >= digest.length - 16; i -= 2) {
    fingerprint += digest.slice(i, i + 2);
  }
  return fingerprint;
}

function sameArray(left: unknown, right: readonly unknown[]) {
  return Array.isArray(left) && left.length === right.length && left.every((value, index) => value === right[index]);
}

function validatePrivateEndpoint(endpointValue: unknown) {
  if(typeof endpointValue !== 'string' || !endpointValue) {
    invalidTarget('is missing its private endpoint');
  }

  let endpoint: URL;
  try {
    endpoint = new URL(endpointValue);
  } catch{
    invalidTarget('contains an invalid private endpoint');
  }

  const hostname = endpoint.hostname.toLowerCase().replace(/\.+$/, '');
  if(
    endpoint.protocol !== 'wss:' ||
    !hostname ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    hostname === 'telegram.org' ||
    hostname.endsWith('.telegram.org') ||
    endpoint.href !== endpointValue
  ) {
    invalidTarget('contains an inconsistent private endpoint');
  }

  return endpointValue;
}

function validatePrivateTarget(target: Record<string, unknown>): MtprotoTarget {
  const endpoint = validatePrivateEndpoint(target.endpoint);
  const fingerprint = target.fingerprint;
  const publicKey = target.publicKey;
  const publicKeyHex = target.publicKeyHex;

  if(typeof fingerprint !== 'string' || !/^[0-9a-f]{16}$/.test(fingerprint)) {
    invalidTarget('contains an invalid private RSA fingerprint');
  }
  if(typeof publicKey !== 'string' || !publicKey.trim()) {
    invalidTarget('is missing its private RSA public key');
  }
  if(!isRecord(publicKeyHex) ||
    typeof publicKeyHex.modulus !== 'string' || !/^[0-9a-f]{512}$/.test(publicKeyHex.modulus) ||
    publicKeyHex.exponent !== '010001') {
    invalidTarget('contains inconsistent private RSA key metadata');
  }
  const normalizedPublicKeyHex: RSAPublicKeyHex = {
    modulus: publicKeyHex.modulus as string,
    exponent: publicKeyHex.exponent as string
  };
  if(!/^-----BEGIN (PUBLIC KEY|RSA PUBLIC KEY)-----\n[A-Za-z0-9+/=\n]+\n-----END \1-----\n?$/.test(publicKey) ||
    /PRIVATE KEY/.test(publicKey) || deriveFingerprint(normalizedPublicKeyHex) !== fingerprint) {
    invalidTarget('contains inconsistent private RSA public key metadata');
  }

  const routeLock = target.routeLock;
  if(!isRecord(routeLock) || routeLock.mode !== 'private' || routeLock.endpoint !== endpoint ||
    routeLock.transport !== 'websocket' || !sameArray(routeLock.dcIds, [1, 2, 3, 4, 5]) ||
    !sameArray(routeLock.connectionTypes, ['client', 'upload', 'download'])) {
    invalidTarget('contains inconsistent private route-lock metadata');
  }

  return Object.freeze({
    mode: 'private',
    endpoint,
    fingerprint,
    publicKey,
    publicKeyHex: Object.freeze({
      modulus: normalizedPublicKeyHex.modulus,
      exponent: normalizedPublicKeyHex.exponent
    }),
    routeLock: Object.freeze({
      mode: 'private',
      endpoint,
      transport: 'websocket',
      dcIds: Object.freeze([...routeLock.dcIds as number[]]),
      connectionTypes: Object.freeze([...routeLock.connectionTypes as ('client' | 'upload' | 'download')[]])
    })
  });
}

export function validateMtprotoTarget(target: unknown): MtprotoTarget {
  if(!isRecord(target)) {
    invalidTarget('is missing');
  }

  if(target.mode === 'telegram') {
    return Object.freeze({mode: 'telegram'});
  }
  if(target.mode === 'private') {
    return validatePrivateTarget(target);
  }

  invalidTarget('has an unknown mode');
}

const embeddedTarget = typeof __MTPROTO_TARGET__ === 'undefined' ?
  undefined : __MTPROTO_TARGET__;

export const MTProtoTarget = validateMtprotoTarget(embeddedTarget);

export function getMtprotoTarget() {
  return MTProtoTarget;
}

export function isPrivateMtprotoTarget() {
  return MTProtoTarget.mode === 'private';
}
