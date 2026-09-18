import {
  assertValidDcId,
  constructTelegramWebSocketUrl,
  resolveMtprotoRoute
} from '@lib/mtproto/dcConfigurator';

const PRIVATE_ENDPOINT = 'wss://private.example.test:2443/apiws';
const WORKER_CONTEXTS = ['main', 'dedicated-worker', 'shared-worker', 'service-worker'] as const;
const privateTarget = {
  mode: 'private' as const,
  endpoint: PRIVATE_ENDPOINT,
  fingerprint: '289f8aeb5aa17de3',
  publicKey: 'embedded rsa public key',
  publicKeyHex: {
    modulus: 'a'.repeat(512),
    exponent: '010001'
  }
};

describe('private MTProto routing', () => {
  it.each(
    [1, 2, 3, 4, 5].flatMap((dcId) =>
      (['client', 'upload', 'download'] as const).flatMap((connectionType) =>
        [false, true].flatMap((premium) =>
          WORKER_CONTEXTS.map((context) =>
            [dcId, connectionType, premium, context] as const
          )
        )
      )
    )
  )('locks %s %s premium=%s to one endpoint in %s', (dcId, connectionType, premium, workerContext) => {
    expect(resolveMtprotoRoute({
      target: privateTarget,
      dcId,
      connectionType,
      transportType: 'websocket',
      premium,
      testMode: false,
      fallbackTransportType: 'websocket',
      workerContext
    })).toEqual({
      dcId,
      connectionType,
      transportType: 'websocket',
      endpoint: PRIVATE_ENDPOINT
    });
  });

  it.each([false, true])('ignores the private test-mode selector %s', (testMode) => {
    expect(resolveMtprotoRoute({
      target: privateTarget,
      dcId: 1,
      connectionType: 'client',
      transportType: 'websocket',
      testMode
    }).endpoint).toBe(PRIVATE_ENDPOINT);
  });

  it.each([1, 2, 3, 4, 5])('keeps migration DC %s logical', (migrationDcId) => {
    expect(resolveMtprotoRoute({
      target: privateTarget,
      dcId: 1,
      migrationDcId,
      connectionType: 'client',
      transportType: 'websocket'
    })).toMatchObject({dcId: migrationDcId, endpoint: PRIVATE_ENDPOINT});
  });

  it.each([0, 6, 1.5, NaN, Infinity, -1])('rejects invalid migration DC %s before routing', (migrationDcId) => {
    expect(() => resolveMtprotoRoute({
      target: privateTarget,
      dcId: 1,
      migrationDcId,
      connectionType: 'client',
      transportType: 'websocket'
    })).toThrow(/invalid dcId/i);
  });

  it.each(['http', 'https'] as const)('rejects private %s transport selection', (transportType) => {
    expect(() => resolveMtprotoRoute({
      target: privateTarget,
      dcId: 5,
      connectionType: 'download',
      transportType
    })).toThrow(/private.*websocket/i);
  });

  it.each(['http', 'https'] as const)('rejects private %s fallback selection', (fallbackTransportType) => {
    expect(() => resolveMtprotoRoute({
      target: privateTarget,
      dcId: 5,
      connectionType: 'client',
      transportType: 'websocket',
      fallbackTransportType
    })).toThrow(/private.*websocket/i);
  });

  it.each([0, 6, 1.5, NaN, Infinity, -1])('rejects invalid DC %s before routing', (dcId) => {
    expect(() => assertValidDcId(dcId)).toThrow(/invalid dcId/i);
  });

  it.each([
    {...privateTarget, endpoint: 'https://private.example.test/apiws'},
    {...privateTarget, endpoint: 'wss://private.example.test/apiws?http=1'},
    {...privateTarget, endpoint: 'wss://telegram.org/apiws'},
    {...privateTarget, endpoint: ''},
    {...privateTarget, fingerprint: ''},
    {...privateTarget, publicKey: ''}
  ])('fails closed for inconsistent embedded metadata', (target) => {
    expect(() => resolveMtprotoRoute({
      target,
      dcId: 1,
      connectionType: 'client',
      transportType: 'websocket'
    })).toThrow(/private.*target|endpoint|fingerprint|public key/i);
  });

  it('keeps ordinary Telegram routing unchanged', () => {
    expect(constructTelegramWebSocketUrl(1, 'client')).toBe('wss://kws1.web.telegram.org/apiws');
  });
});
