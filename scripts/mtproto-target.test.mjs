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
import {inspect} from 'node:util';
import {afterAll, describe, expect, it} from 'vitest';
import * as mtprotoTarget from './mtproto-target.mjs';
const {assertRunnableMtprotoTarget, resolveMtprotoTarget} = mtprotoTarget;

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

  it('does not retain malformed endpoint credentials in the complete error', () => {
    const credentialMarker = 'credential-marker';
    let thrown;
    try {
      resolveMtprotoTarget(privateEnv({
        MTPROTO_PRIVATE_ENDPOINT: `wss://build-user:${credentialMarker}@%`
      }));
    } catch(error) {
      thrown = error;
    }

    const rendered = inspect(thrown, {depth: null});
    expect(rendered).toMatch(/must be an absolute wss URL/);
    expect(rendered).not.toContain(credentialMarker);
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
    const target = resolveMtprotoTarget(privateEnv({
      MTPROTO_PRIVATE_ENDPOINT: 'WSS://PRIVATE.Example.Test.:2443/a/../apiws'
    }));
    expect(target).toMatchObject({
      mode: 'private',
      endpoint: 'wss://private.example.test:2443/apiws',
      fingerprint: '289f8aeb5aa17de3',
      publicKey: fixtureKey
    });
    const jwk = createPublicKey(fixtureKey).export({format: 'jwk'});
    expect(target.publicKeyHex).toEqual({
      modulus: Buffer.from(jwk.n, 'base64url').toString('hex'),
      exponent: Buffer.from(jwk.e, 'base64url').toString('hex')
    });
  });

  it('allows a validated private target to emit a runnable artifact', () => {
    const target = resolveMtprotoTarget(privateEnv());
    expect(target.routeLock).toEqual({
      mode: 'private',
      endpoint: 'wss://private.example.test:2443/apiws',
      transport: 'websocket',
      dcIds: [1, 2, 3, 4, 5],
      connectionTypes: ['client', 'upload', 'download']
    });
    expect(() => assertRunnableMtprotoTarget(target)).not.toThrow();
  });

  it('emits a self-identifying private Vite artifact with a restrictive CSP', () => {
    const {outputDirectory, result} = buildPrivateTarget();

    expect(result.status).toBe(0);
    expect(existsSync(outputDirectory)).toBe(true);
    const manifest = JSON.parse(readFileSync(join(outputDirectory, 'mtproto-target.json'), 'utf8'));
    expect(manifest).toMatchObject({
      mode: 'private',
      endpoint: 'wss://private.example.test:2443/apiws',
      fingerprint: '289f8aeb5aa17de3',
      sourceCommit: expect.stringMatching(/^[0-9a-f]{40}$/),
      artifactDigest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/)
    });
    const index = readFileSync(join(outputDirectory, 'index.html'), 'utf8').replaceAll('&#39;', "'");
    expect(index).toContain('Content-Security-Policy');
    expect(index).toContain("connect-src 'self' wss://private.example.test:2443/apiws");
    const executable = readdirSync(outputDirectory)
    .filter((file) => file.endsWith('.js'))
    .map((file) => readFileSync(join(outputDirectory, file), 'utf8'))
    .join('\n');
    expect(executable).toContain('289f8aeb5aa17de3');
    expect(executable).not.toMatch(/(?:kws[1-5]|apiw(?:_test1|1))\.web\.telegram\.org|\bapiw(?:_test1|1)\b/i);
    expect(executable).not.toContain('c3b42b026ce86b21');
    expect(mtprotoTarget.verifyPrivateArtifactManifest(outputDirectory)).toEqual(manifest);
  }, 60_000);

  it('fails private artifact verification after a completed artifact is changed', () => {
    const {outputDirectory, result} = buildPrivateTarget();
    expect(result.status).toBe(0);

    const executable = readdirSync(outputDirectory).find((file) => file.endsWith('.js'));
    expect(executable).toBeTruthy();
    writeFileSync(join(outputDirectory, executable), readFileSync(join(outputDirectory, executable)) + '\n// tampered');
    expect(() => mtprotoTarget.verifyPrivateArtifactManifest(outputDirectory)).toThrow(/digest/i);
  }, 60_000);

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
