import 'fake-indexeddb/auto';
import {webcrypto} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const [context, entryFile] = process.argv.slice(2);

function defineGlobal(name, value) {
  Object.defineProperty(globalThis, name, {
    configurable: true,
    enumerable: true,
    value,
    writable: true
  });
}

class WorkerScope {}
class SharedWorkerScope extends WorkerScope {}
class ServiceWorkerScope extends WorkerScope {}

defineGlobal('WorkerGlobalScope', WorkerScope);
defineGlobal('DedicatedWorkerGlobalScope', WorkerScope);
defineGlobal('SharedWorkerGlobalScope', SharedWorkerScope);
defineGlobal('ServiceWorkerGlobalScope', ServiceWorkerScope);

const scope = context === 'service-worker' ? ServiceWorkerScope.prototype :
  context === 'shared-worker' ? SharedWorkerScope.prototype : WorkerScope.prototype;
Object.setPrototypeOf(globalThis, scope);

defineGlobal('self', globalThis);
defineGlobal('location', new URL('http://localhost/'));
defineGlobal('navigator', {hardwareConcurrency: 4, userAgent: 'Node.js'});
defineGlobal('crypto', webcrypto);
defineGlobal('addEventListener', () => {});
defineGlobal('removeEventListener', () => {});
defineGlobal('postMessage', () => {});
defineGlobal('close', () => {});
defineGlobal('clients', {matchAll: async() => [], claim: async() => {}});
defineGlobal('caches', {delete: async() => true, open: async() => ({})});
defineGlobal('skipWaiting', async() => {});
defineGlobal('WindowClient', class {});
defineGlobal('__mtprotoRoutes', []);

try {
  await import(pathToFileURL(entryFile).href + `?context=${context}`);
  const output = JSON.stringify(globalThis.__mtprotoRoutes);
  process.stdout.write(`__MT_PROTO_ROUTES__${output}`, () => process.exit(0));
} catch(error) {
  console.error(error?.stack || error);
  process.exit(1);
}
