import {afterAll, describe, expect, it} from 'vitest';
import {join, resolve} from 'node:path';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolveMtprotoTarget} from './mtproto-target.mjs';
import {
  PRIVATE_WORKER_ENTRIES,
  buildPrivateWorkerEntry,
  runPrivateWorkerEntry
} from './mtproto-worker-build.mjs';

const PRIVATE_ENDPOINT = 'wss://private.example.test:2443/apiws';
const privateTarget = resolveMtprotoTarget({
  MTPROTO_TARGET_MODE: 'private',
  MTPROTO_PRIVATE_ENDPOINT: PRIVATE_ENDPOINT,
  MTPROTO_PRIVATE_RSA_PUBLIC_KEY_FILE: resolve('scripts/fixtures/private-mtproto-public.pem')
});
const temporaryDirectories = [];

afterAll(() => {
  for(const directory of temporaryDirectories) {
    rmSync(directory, {recursive: true, force: true});
  }
});

describe('private MTProto worker routing', () => {
  it('runs every compiled worker dialer against the embedded WSS endpoint', async() => {
    for(const {context, entry} of PRIVATE_WORKER_ENTRIES) {
      const outputDirectory = mkdtempSync(join(tmpdir(), 'mtproto-worker-routing-'));
      temporaryDirectories.push(outputDirectory);

      const output = await buildPrivateWorkerEntry({
        context,
        entry,
        outputDirectory,
        target: privateTarget
      });
      const routes = runPrivateWorkerEntry({
        context,
        entryFile: output.entryFile
      });

      expect(routes).toHaveLength(30);
      expect(routes.every((route) =>
        route.context === context &&
        route.route === PRIVATE_ENDPOINT &&
        route.dial === PRIVATE_ENDPOINT &&
        Array.isArray(route.dials) &&
        route.dials.length === 1 &&
        route.dials.every((dial) =>
          dial.dcId === route.dcId &&
          dial.url === PRIVATE_ENDPOINT
        )
      )).toBe(true);
      expect(output.bundle).toContain(PRIVATE_ENDPOINT);
    }
  });
});
