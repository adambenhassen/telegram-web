import {afterAll, beforeAll, describe, expect, it, vi} from 'vitest';
import {createPrivateWorkerBlobURL} from '@helpers/createPrivateWorkerBlobURL';

const PRIVATE_ENDPOINT = 'wss://private.example.test:2443/apiws';
const privateTarget = {
  mode: 'private' as const,
  endpoint: PRIVATE_ENDPOINT,
  fingerprint: 'c94b4d28b2d215b8',
  publicKey: '-----BEGIN RSA PUBLIC KEY-----\nAA==\n-----END RSA PUBLIC KEY-----',
  publicKeyHex: {
    modulus: 'a'.repeat(512),
    exponent: '010001'
  },
  routeLock: {
    mode: 'private' as const,
    endpoint: PRIVATE_ENDPOINT,
    transport: 'websocket' as const,
    dcIds: [1, 2, 3, 4, 5] as const,
    connectionTypes: ['client', 'upload', 'download'] as const
  }
};

class FakeWebSocket extends EventTarget {
  public static urls: string[] = [];
  public binaryType = 'arraybuffer';

  constructor(public url: string, _protocol: string) {
    super();
    FakeWebSocket.urls.push(url);
  }

  public send(_body: ArrayBufferView) {}
  public close() {}
}

type Socket = typeof import('@lib/mtproto/transports/websocket').default;
let PrivateSocket: Socket;

describe('private MTProto browser egress policy', () => {
  const originalCreateObjectURL = URL.createObjectURL;

  beforeAll(async() => {
    vi.doMock('@config/mtprotoTarget', () => ({
      MTProtoTarget: privateTarget,
      getMtprotoTarget: () => privateTarget,
      isPrivateMtprotoTarget: () => true,
      validateMtprotoTarget: (target: unknown) => target
    }));
    ({default: PrivateSocket} = await import('@lib/mtproto/transports/websocket'));
  });

  afterAll(() => {
    vi.doUnmock('@config/mtprotoTarget');
    vi.resetModules();
    if(originalCreateObjectURL) {
      Object.defineProperty(URL, 'createObjectURL', {
        configurable: true,
        value: originalCreateObjectURL
      });
    } else {
      delete (URL as typeof URL & {createObjectURL?: typeof URL.createObjectURL}).createObjectURL;
    }
  });

  it('loads a worker source as a blob URL for the private CSP policy container', async() => {
    const createObjectURL = vi.fn(() => 'blob:private-mtproto-worker');
    const fetchWorker = vi.fn(async() => ({
      ok: true,
      text: async() => 'self.addEventListener("message", () => {});'
    }));
    const originalFetch = globalThis.fetch;
    vi.stubGlobal('fetch', fetchWorker);
    Object.defineProperty(URL, 'createObjectURL', {
      configurable: true,
      value: createObjectURL
    });

    try {
      await expect(createPrivateWorkerBlobURL('index.worker.js')).resolves.toBe('blob:private-mtproto-worker');
      expect(fetchWorker).toHaveBeenCalledWith('index.worker.js');
      expect(createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    } finally {
      vi.stubGlobal('fetch', originalFetch);
    }
  });

  it('allows the configured WSS endpoint and blocks an unconfigured origin at the browser dial boundary', () => {
    FakeWebSocket.urls = [];
    vi.stubGlobal('WebSocket', FakeWebSocket);

    const allowed = new PrivateSocket(1, PRIVATE_ENDPOINT, '');
    expect(FakeWebSocket.urls).toEqual([PRIVATE_ENDPOINT]);
    allowed.close();

    expect(() => new PrivateSocket(1, 'wss://unconfigured.example.test/apiws', '')).toThrow(/private.*endpoint/i);
    expect(FakeWebSocket.urls).toEqual([PRIVATE_ENDPOINT]);
  });
});
