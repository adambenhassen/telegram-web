export type RSAPublicKeyHex = {
  modulus: string,
  exponent: string
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
    readonly publicKeyHex: RSAPublicKeyHex
  };

declare const __MTPROTO_TARGET__: MtprotoTarget | undefined;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function invalidTarget(message: string): never {
  throw new Error('[MT] embedded target metadata ' + message);
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

  return Object.freeze({
    mode: 'private',
    endpoint,
    fingerprint,
    publicKey,
    publicKeyHex: Object.freeze({
      modulus: publicKeyHex.modulus,
      exponent: publicKeyHex.exponent
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
