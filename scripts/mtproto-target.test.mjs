import {generateKeyPairSync} from 'node:crypto';
import {mkdtempSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {describe, expect, it} from 'vitest';
import {assertRunnableMtprotoTarget, resolveMtprotoTarget} from './mtproto-target.mjs';

const fixturePath = resolve('scripts/fixtures/private-mtproto-public.pem');
const fixtureKey = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAt0XATe6T6yIGpzy/ZTTulB8sROFQJU/Oo8dKKEHQd5S30CHfkcDE
jeYOOspc7zHv5ZrM9eQfJ3LelIsP1u6p1iZWchkAhf/UsHzN3P31gh6sjRV/SuBo
8YM1gJ1lq6286j9Ht4Ek1uD0gXVBQzlap5KvH0sD8OJRSjIH+PA9TzYSjfmyK1+q
M+dwTXP2qFNgZ1oc9c9zm92xF9TwC5Z7ZPNlMSHBozC8R+HFq27JVXiCSL1lAunt
6NtFavrBmttvDkEHkWeglSWHWHLWjUGP3H49tcqvs1GflY1YQeruxNK2ynEr47iF
t5fHT9B6HtX1XBdGsYF39yjOMjZETrYB6wIDAQAB
-----END RSA PUBLIC KEY-----\n`;

function privateEnv(overrides = {}) {
  return {
    MTPROTO_TARGET_MODE: 'private',
    MTPROTO_PRIVATE_ENDPOINT: 'wss://private.example.test:2443/apiws',
    MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: fixturePath,
    ...overrides
  };
}

function writeKey(contents) {
  const directory = mkdtempSync(join(tmpdir(), 'mtproto-target-'));
  const keyPath = join(directory, 'key.pem');
  writeFileSync(keyPath, contents);
  return keyPath;
}

describe('MTProto build target', () => {
  it('keeps the default Telegram target unchanged', () => {
    expect(resolveMtprotoTarget({})).toEqual({mode: 'telegram'});
  });

  it.each([
    ['endpoint is omitted', {MTPROTO_PRIVATE_ENDPOINT: undefined}],
    ['endpoint is empty', {MTPROTO_PRIVATE_ENDPOINT: '  '}],
    ['key file is omitted', {MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: undefined}],
    ['key file is empty', {MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: '\t'}]
  ])('rejects private mode when the %s', (_name, overrides) => {
    expect(() => resolveMtprotoTarget(privateEnv(overrides))).toThrow(/requires non-empty/);
  });

  it('rejects alternate private-target fields', () => {
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_ENDPOINT_2: 'wss://other.example.test'})))
    .toThrow(/unrecognized.*MTPROTO_PRIVATE_ENDPOINT_2/i);
  });

  it.each([
    'https://private.example.test/apiws',
    'wss://user:pass@private.example.test/apiws',
    'wss://private.example.test/apiws?dc=1',
    'wss://private.example.test/apiws#target',
    'wss:///apiws',
    'not a URL',
    'wss://telegram.org/apiws',
    'wss://KWS2.WEB.TELEGRAM.ORG./apiws'
  ])('rejects private endpoint %s', (endpoint) => {
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_ENDPOINT: endpoint}))).toThrow();
  });

  it('rejects an unreadable key file', () => {
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: '/does/not/exist.pem'})))
    .toThrow(/read.*public key/i);
  });

  it.each([
    ['malformed PEM', 'not a key'],
    ['additional text', `${fixtureKey}unexpected`],
    ['additional PEM object', `${fixtureKey}${fixtureKey}`]
  ])('rejects %s', (_name, contents) => {
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: writeKey(contents)})))
    .toThrow(/exactly one public RSA key/i);
  });

  it('rejects private key material', () => {
    const {privateKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
    const keyPath = writeKey(privateKey.export({type: 'pkcs8', format: 'pem'}));
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath})))
    .toThrow(/private key material/i);
  });

  it.each([
    ['1024-bit modulus', {modulusLength: 1024}],
    ['exponent 3', {modulusLength: 2048, publicExponent: 3}]
  ])('rejects an RSA key with a %s', (_name, options) => {
    const {publicKey} = generateKeyPairSync('rsa', options);
    const keyPath = writeKey(publicKey.export({type: 'spki', format: 'pem'}));
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath})))
    .toThrow(/2048-bit RSA.*exponent 65537/);
  });

  it('normalizes and exposes one atomic private target', () => {
    expect(resolveMtprotoTarget(privateEnv({
      MTPROTO_PRIVATE_ENDPOINT: 'WSS://PRIVATE.Example.Test.:2443/a/../apiws'
    }))).toEqual({
      mode: 'private',
      endpoint: 'wss://private.example.test:2443/apiws',
      fingerprint: '289f8aeb5aa17de3',
      publicKey: fixtureKey
    });
  });

  it('stops a validated private target before routing can emit a runnable artifact', () => {
    const target = resolveMtprotoTarget(privateEnv());
    expect(() => assertRunnableMtprotoTarget(target)).toThrow(
      /validated.*wss:\/\/private\.example\.test:2443\/apiws.*289f8aeb5aa17de3.*no runnable artifact/i
    );
  });
});
