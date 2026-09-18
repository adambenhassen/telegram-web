import {afterAll, beforeAll, describe, expect, it, vi} from 'vitest';
import {
  assertValidDcId,
  constructTelegramWebSocketUrl,
  resolveMtprotoRoute
} from '@lib/mtproto/dcConfigurator';
import {validateMtprotoTarget} from '@config/mtprotoTarget';

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
const embeddedPrivateTarget = validateMtprotoTarget(privateTarget);

class FakeSocket extends EventTarget {
  constructor(
    public dcId: number,
    public url: string,
    public logSuffix: string
  ) {
    super();
  }

  public send(_data: Uint8Array) {}

  public close() {
    this.dispatchEvent(new Event('close'));
  }
}

type PrivateDcConfiguratorModule = typeof import('@lib/mtproto/dcConfigurator');
type PrivateModesModule = typeof import('@config/modes');
type PrivateHttp = typeof import('@lib/mtproto/transports/http').default;
type PrivateTransportController = typeof import('@lib/mtproto/transports/controller').default;
type PrivateTcpObfuscated = typeof import('@lib/mtproto/transports/tcpObfuscated').default;

let privateDcConfigurator: PrivateDcConfiguratorModule;
let privateModes: PrivateModesModule;
let PrivateHTTP: PrivateHttp;
let privateTransportController: PrivateTransportController;
let PrivateTcpObfuscated: PrivateTcpObfuscated;

describe('private MTProto routing', () => {
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

describe('private embedded target runtime routing', () => {
  const originalUrl = location.href;

  beforeAll(async() => {
    history.replaceState({}, '', '/?test=1&http=1');
    vi.resetModules();
    vi.doMock('@config/mtprotoTarget', () => ({
      MTProtoTarget: embeddedPrivateTarget,
      getMtprotoTarget: () => embeddedPrivateTarget,
      isPrivateMtprotoTarget: () => true,
      validateMtprotoTarget: (target: unknown) => target
    }));
    vi.doMock('@lib/mtproto/transports/websocket', () => ({default: FakeSocket}));

    [privateDcConfigurator, privateModes, {default: PrivateHTTP}, {default: privateTransportController}, {default: PrivateTcpObfuscated}] = await Promise.all([
      import('@lib/mtproto/dcConfigurator'),
      import('@config/modes'),
      import('@lib/mtproto/transports/http'),
      import('@lib/mtproto/transports/controller'),
      import('@lib/mtproto/transports/tcpObfuscated')
    ]);
  });

  afterAll(() => {
    history.replaceState({}, '', originalUrl);
    vi.doUnmock('@config/mtprotoTarget');
    vi.doUnmock('@lib/mtproto/transports/websocket');
    vi.resetModules();
  });

  it('freezes test and HTTP query selectors and skips auth test-mode rewrites', () => {
    expect(privateModes.default.test).toBe(false);
    expect(privateModes.default.http).toBe(false);
    expect(privateModes.default.multipleTransports).toBe(false);
    expect(privateModes.default.transport).toBe('websocket');
    expect(privateModes.shouldRewriteAuthTestMode(true)).toBe(false);
    expect(privateModes.shouldRewriteAuthTestMode(false)).toBe(false);
  });

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
  )('uses the embedded WSS endpoint from %s in %s (%s, premium=%s)', (dcId, connectionType, premium, workerContext) => {
    const configurator = new privateDcConfigurator.DcConfigurator();
    const transport = configurator.chooseServer(dcId, connectionType, 'websocket', false, premium);
    const transportUrl = (transport as unknown as {url: string}).url;

    expect({workerContext, route: privateDcConfigurator.constructTelegramWebSocketUrl(dcId, connectionType, premium), transport: transportUrl}).toEqual({
      workerContext,
      route: PRIVATE_ENDPOINT,
      transport: PRIVATE_ENDPOINT
    });

    transport.destroy();
  });

  it.each(['http', 'https'] as const)('rejects private %s through the real server selector', (transportType) => {
    expect(() => new privateDcConfigurator.DcConfigurator().chooseServer(1, 'client', transportType, false)).toThrow(/private.*websocket/i);
  });

  it('does not probe HTTP or WebSocket transports in private mode', async() => {
    await expect(privateTransportController.pingTransports()).resolves.toEqual({https: false, websocket: true});
    await expect(privateTransportController.waitForWebSocket()).resolves.toBeUndefined();
    expect(() => new PrivateHTTP(1, 'https://telegram.org/apiw1', '')).toThrow(/private.*HTTP/i);
  });

  it('keeps the private endpoint immutable in the real TCP dialer', () => {
    const transport = new PrivateTcpObfuscated(FakeSocket as any, 1, PRIVATE_ENDPOINT, '', 3000);

    expect(() => transport.changeUrl('wss://other.example.test/apiws')).toThrow(/endpoint is immutable/i);
    transport.destroy();
  });
});
