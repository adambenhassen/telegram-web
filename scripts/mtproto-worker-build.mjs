import {spawnSync} from 'node:child_process';
import {join, resolve} from 'node:path';
import {writeFileSync} from 'node:fs';
import {build} from 'vite';
import solidPlugin from 'vite-plugin-solid';

const ROOT = resolve('.');
const ROUTE_PROBE_ID = '\0mtproto-route-probe';
const SOCKET_STUB_ID = resolve(ROOT, 'scripts/mtproto-test-socket.virtual.mjs');

export const PRIVATE_WORKER_ENTRIES = [
  {context: 'dedicated-worker', entry: 'src/lib/mainWorker/index.worker.ts'},
  {context: 'shared-worker', entry: 'src/lib/mainWorker/index.worker.ts'},
  {context: 'service-worker', entry: 'sw.ts'}
];

const aliases = {
  'solid-transition-group': resolve(ROOT, 'src/vendor/solid-transition-group'),
  '@components': resolve(ROOT, 'src/components'),
  '@helpers': resolve(ROOT, 'src/helpers'),
  '@hooks': resolve(ROOT, 'src/hooks'),
  '@stores': resolve(ROOT, 'src/stores'),
  '@lib/mtproto/transports/websocket': SOCKET_STUB_ID,
  '@lib': resolve(ROOT, 'src/lib'),
  '@appManagers': resolve(ROOT, 'src/lib/appManagers'),
  '@richTextProcessor': resolve(ROOT, 'src/lib/richTextProcessor'),
  '@environment': resolve(ROOT, 'src/environment'),
  '@customEmoji': resolve(ROOT, 'src/lib/customEmoji'),
  '@config': resolve(ROOT, 'src/config'),
  '@vendor': resolve(ROOT, 'src/vendor'),
  '@layer': resolve(ROOT, 'src/layer'),
  '@types': resolve(ROOT, 'src/types'),
  '@': resolve(ROOT, 'src')
};

const routeProbe = `
import {DcConfigurator, constructTelegramWebSocketUrl} from '@lib/mtproto/dcConfigurator';
import {getMtprotoTarget} from '@config/mtprotoTarget';
import {assertPrivateMtprotoWebSocketEndpoint} from '@lib/mtproto/endpointPolicy';

const context = typeof ServiceWorkerGlobalScope !== 'undefined' && self instanceof ServiceWorkerGlobalScope ?
  'service-worker' : typeof SharedWorkerGlobalScope !== 'undefined' && self instanceof SharedWorkerGlobalScope ?
    'shared-worker' : 'dedicated-worker';
globalThis.__mtprotoRoutes ??= [];
globalThis.__mtprotoDials ??= [];
let privatePolicyBlockedUnconfigured = false;
try {
  assertPrivateMtprotoWebSocketEndpoint(getMtprotoTarget(), 'wss://unconfigured.example.test/apiws');
} catch {
  privatePolicyBlockedUnconfigured = true;
}
for(const dcId of [1, 2, 3, 4, 5]) {
  for(const connectionType of ['client', 'upload', 'download']) {
    for(const premium of [false, true]) {
      const dialStart = globalThis.__mtprotoDials.length;
      const transport = new DcConfigurator().chooseServer(dcId, connectionType, 'websocket', false, premium);
      globalThis.__mtprotoRoutes.push({
        context,
        dcId,
        connectionType,
        premium,
        route: constructTelegramWebSocketUrl(dcId, connectionType, premium),
        dial: transport.url,
        privatePolicyAllowsConfigured: (() => {
          assertPrivateMtprotoWebSocketEndpoint(getMtprotoTarget(), transport.url);
          return true;
        })(),
        privatePolicyBlockedUnconfigured,
        dials: globalThis.__mtprotoDials.slice(dialStart)
      });
      transport.destroy();
    }
  }
}
`;

const socketStub = `
export default class FakeSocket {
  constructor(dcId, url, logSuffix) {
    this.listeners = new Map();
    globalThis.__mtprotoDials ??= [];
    globalThis.__mtprotoDials.push({dcId, url, logSuffix});
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type, listener) {
    const listeners = this.listeners.get(type);
    if(!listeners) return;
    this.listeners.set(type, listeners.filter((entry) => entry !== listener));
  }

  send() {}
  close() {}
}
`;

function routingPlugin() {
  return {
    name: 'mtproto-worker-routing-test',
    enforce: 'pre',

    resolveId(source) {
      if(source === 'virtual:mtproto-route-probe') return ROUTE_PROBE_ID;
      if(source === '@lib/mtproto/transports/websocket') return SOCKET_STUB_ID;
    },

    load(id) {
      if(id === ROUTE_PROBE_ID) return routeProbe;
      if(id === SOCKET_STUB_ID) return socketStub;
    },

    transform(code, id) {
      if(id.endsWith('/src/lib/mainWorker/index.worker.ts') || id.endsWith('/sw.ts')) {
        return {
          code: `import 'virtual:mtproto-route-probe';\n${code}`,
          map: null
        };
      }
    }
  };
}

export async function buildPrivateWorkerEntry({context, entry, outputDirectory, target}) {
  writeFileSync(join(outputDirectory, 'package.json'), '{"type":"module"}');

  const result = await build({
    configFile: false,
    root: ROOT,
    define: {
      __MTPROTO_TARGET__: JSON.stringify(target),
      __MTPROTO_PRIVATE__: JSON.stringify(target.mode === 'private'),
      'import.meta.env.VITE_MTPROTO_HAS_WS': 'true',
      'import.meta.env.VITE_MTPROTO_HAS_HTTP': 'true',
      'import.meta.env.VITE_MTPROTO_AUTO': 'false',
      'import.meta.env.VITE_MTPROTO_SW': JSON.stringify(context === 'service-worker')
    },
    plugins: [routingPlugin(), solidPlugin()],
    resolve: {alias: aliases},
    build: {
      outDir: outputDirectory,
      write: true,
      minify: false,
      sourcemap: false,
      emptyOutDir: false,
      rollupOptions: {
        input: resolve(ROOT, entry)
      }
    }
  });

  const output = Array.isArray(result) ? result[0] : result;
  const entryChunk = output.output.find((file) => file.type === 'chunk' && file.isEntry);
  if(!entryChunk) {
    throw new Error(`No entry chunk emitted for ${entry}`);
  }

  return {
    entryFile: join(outputDirectory, entryChunk.fileName),
    bundle: output.output
      .filter((file) => file.type === 'chunk')
      .map((file) => file.code)
      .join('\n')
  };
}

export function runPrivateWorkerEntry({context, entryFile}) {
  const result = spawnSync(process.execPath, [
    resolve(ROOT, 'scripts/mtproto-worker-runtime.mjs'),
    context,
    entryFile
  ], {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 120_000
  });

  if(result.error || result.status !== 0) {
    throw new Error([
      `Unable to run ${context} MTProto entry`,
      result.error?.message,
      result.stdout,
      result.stderr
    ].filter(Boolean).join('\n'));
  }

  const marker = '__MT_PROTO_ROUTES__';
  const markerIndex = result.stdout.lastIndexOf(marker);
  if(markerIndex < 0) {
    throw new Error(`No MTProto route output from ${context} MTProto entry:\n${result.stdout}`);
  }

  return JSON.parse(result.stdout.slice(markerIndex + marker.length));
}
