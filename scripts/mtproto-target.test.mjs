import {createPublicKey, generateKeyPairSync} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {afterAll, describe, expect, it} from 'vitest';
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
const temporaryDirectories = [];

function temporaryDirectory() {
  const directory = mkdtempSync(join(tmpdir(), 'mtproto-target-'));
  temporaryDirectories.push(directory);
  return directory;
}

afterAll(() => {
  for(const directory of temporaryDirectories) {
    rmSync(directory, {recursive: true, force: true});
  }
});

function privateEnv(overrides = {}) {
  return {
    MTPROTO_TARGET_MODE: 'private',
    MTPROTO_PRIVATE_ENDPOINT: 'wss://private.example.test:2443/apiws',
    MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: fixturePath,
    ...overrides
  };
}

function writeKey(contents) {
  const directory = temporaryDirectory();
  const keyPath = join(directory, 'key.pem');
  writeFileSync(keyPath, contents);
  return keyPath;
}

function pem(label, der, lineLength = 64) {
  const payload = der.toString('base64').match(new RegExp(`.{1,${lineLength}}`, 'g')).join('\n');
  return `-----BEGIN ${label}-----\n${payload}\n-----END ${label}-----\n`;
}

function buildPrivateTarget(overrides = {}, outputDirectory = join(temporaryDirectory(), 'dist')) {
  const env = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    name !== 'MTPROTO_TARGET_MODE' && !name.startsWith('MTPROTO_PRIVATE_')
  ));
  const result = spawnSync(process.execPath, [
    resolve('node_modules/vite/bin/vite.js'),
    'build',
    '--outDir',
    outputDirectory
  ], {
    cwd: process.cwd(),
    encoding: 'utf8',
    env: {...env, ...privateEnv(overrides)}
  });
  return {outputDirectory, result};
}

describe('MTProto build target', () => {
  it('keeps the default Telegram target unchanged', () => {
    expect(resolveMtprotoTarget({})).toEqual({mode: 'telegram'});
  });

  it.each(['', 'privatee', 'TELEGRAM'])('rejects an empty or unknown target mode %j', (mode) => {
    expect(() => resolveMtprotoTarget({MTPROTO_TARGET_MODE: mode})).toThrow(/either telegram or private/);
  });

  it('rejects private fields in Telegram mode', () => {
    expect(() => resolveMtprotoTarget({
      MTPROTO_TARGET_MODE: 'telegram',
      MTPROTO_PRIVATE_ENDPOINT: 'wss://private.example.test/apiws'
    })).toThrow(/private.*fields require.*private/i);
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

  it('rejects an unknown private-target field without reading its value', () => {
    const env = privateEnv();
    Object.defineProperty(env, 'MTPROTO_PRIVATE_SECRET', {
      enumerable: true,
      get() {
        throw new Error('secret value was read');
      }
    });

    expect(() => resolveMtprotoTarget(env)).toThrow(/unrecognized.*MTPROTO_PRIVATE_SECRET/i);
  });

  it.each([
    'https://private.example.test/apiws',
    'wss://user:pass@private.example.test/apiws',
    'wss://private.example.test/apiws?dc=1',
    'wss://private.example.test/apiws#target',
    'wss:///apiws',
    'not a URL',
    'wss://telegram.org/apiws',
    'wss://KWS2.WEB.TELEGRAM.ORG./apiws',
    'wss://ＴＥＬＥＧＲＡＭ．ＯＲＧ/apiws'
  ])('rejects private endpoint %s', (endpoint) => {
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_ENDPOINT: endpoint}))).toThrow();
  });

  it('rejects an unreadable key file', () => {
    const keyPath = '/does/not/exist-sensitive-key.pem';
    let thrown;
    try {
      resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath}));
    } catch(error) {
      thrown = error;
    }
    expect(thrown.message).toMatch(/read.*public key/i);
    expect(thrown.message).not.toContain(keyPath);
  });

  it.each([
    ['non-regular', () => temporaryDirectory()],
    ['oversized', () => writeKey('A'.repeat(32 * 1024))]
  ])('rejects a %s key file without disclosing its path', (_name, makeKeyPath) => {
    const keyPath = makeKeyPath();
    let thrown;
    try {
      resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath}));
    } catch(error) {
      thrown = error;
    }
    expect(thrown.message).toMatch(/read.*public key/i);
    expect(thrown.message).not.toContain(keyPath);
  });

  it.each([
    ['malformed PEM', 'not a key'],
    ['malformed base64', '-----BEGIN PUBLIC KEY-----\n%%%\n-----END PUBLIC KEY-----\n'],
    ['malformed DER', pem('PUBLIC KEY', Buffer.from([1, 2, 3]))],
    ['additional text', `${fixtureKey}unexpected`],
    ['additional PEM object', `${fixtureKey}${fixtureKey}`]
  ])('rejects %s', (_name, contents) => {
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: writeKey(contents)})))
    .toThrow(/exactly one public RSA key/i);
  });

  it.each(['pkcs1', 'pkcs8'])('rejects %s private key material', (type) => {
    const {privateKey} = generateKeyPairSync('rsa', {modulusLength: 2048});
    const keyPath = writeKey(privateKey.export({type, format: 'pem'}));
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath})))
    .toThrow(/private key material/i);
  });

  it.each(['public', 'private'])('rejects appended %s DER inside one public PEM block', (kind) => {
    const firstKey = createPublicKey(fixtureKey).export({type: 'spki', format: 'der'});
    const keyPair = generateKeyPairSync('rsa', {modulusLength: 2048});
    const appendedKey = kind === 'public' ?
      keyPair.publicKey.export({type: 'spki', format: 'der'}) :
      keyPair.privateKey.export({type: 'pkcs8', format: 'der'});
    const keyPath = writeKey(pem('PUBLIC KEY', Buffer.concat([firstKey, appendedKey])));

    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath})))
    .toThrow(/exactly one public RSA key/i);
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

  it('rejects a non-RSA public key', () => {
    const {publicKey} = generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
    const keyPath = writeKey(publicKey.export({type: 'spki', format: 'pem'}));
    expect(() => resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath})))
    .toThrow(/2048-bit RSA.*exponent 65537/);
  });

  it.each([
    ['PKCS#1', 'RSA PUBLIC KEY', 'pkcs1'],
    ['SPKI', 'PUBLIC KEY', 'spki']
  ])('accepts canonical %s DER and regenerates canonical PEM', (_name, label, type) => {
    const key = createPublicKey(fixtureKey);
    const der = key.export({type, format: 'der'});
    const keyPath = writeKey(pem(label, der, 37));

    expect(resolveMtprotoTarget(privateEnv({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath}))).toMatchObject({
      fingerprint: '289f8aeb5aa17de3',
      publicKey: key.export({type, format: 'pem'}).toString()
    });
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

  it('fails a private Vite build before creating its output directory', () => {
    const {outputDirectory, result} = buildPrivateTarget();

    expect(result.status).not.toBe(0);
    expect(existsSync(outputDirectory)).toBe(false);
    expect(`${result.stdout}${result.stderr}`).toMatch(/no runnable artifact/i);
    expect(`${result.stdout}${result.stderr}`).not.toContain(fixturePath);
  });

  it('does not rewrite existing output when private validation fails', () => {
    const keyPath = writeKey('not a key');
    const outputDirectory = join(temporaryDirectory(), 'dist');
    mkdirSync(outputDirectory);
    const sentinelPath = join(outputDirectory, 'sentinel.txt');
    writeFileSync(sentinelPath, 'keep this artifact');
    const {result} = buildPrivateTarget({MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: keyPath}, outputDirectory);

    expect(result.status).not.toBe(0);
    expect(readdirSync(outputDirectory)).toEqual(['sentinel.txt']);
    expect(readFileSync(sentinelPath, 'utf8')).toBe('keep this artifact');
    expect(`${result.stdout}${result.stderr}`).not.toContain(keyPath);
    expect(`${result.stdout}${result.stderr}`).not.toContain('not a key');
  });
});
