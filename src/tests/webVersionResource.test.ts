import {readFileSync} from 'node:fs';
import {describe, expect, it, vi} from 'vitest';
import webVersionResourcePlugin from '@/scripts/webVersionResource';
import {hasWebVersionUpdate, WEB_VERSION_RESOURCE_PATH} from '@lib/webVersion';

const fullVersion = '2.2 (676)';

function createPlugin() {
  const plugin = webVersionResourcePlugin();
  const configResolved = plugin.configResolved as unknown as (config: {env: {VITE_VERSION_FULL: string}}) => void;
  configResolved({env: {VITE_VERSION_FULL: fullVersion}});
  return plugin;
}

describe('Web version resource', () => {
  it('emits the raw full version at the well-known path on every build', () => {
    const plugin = createPlugin();
    const emitFile = vi.fn();
    const generateBundle = plugin.generateBundle as unknown as (this: {emitFile: typeof emitFile}) => void;

    generateBundle.call({emitFile});

    expect(emitFile).toHaveBeenCalledOnce();
    expect(emitFile).toHaveBeenCalledWith({
      type: 'asset',
      fileName: '.well-known/telegram-web/version.txt',
      source: fullVersion
    });
  });

  it('serves the resource as uncached plain text in development', () => {
    const plugin = createPlugin();
    const use = vi.fn();
    const configureServer = plugin.configureServer as unknown as (server: {middlewares: {use: typeof use}}) => void;
    configureServer({middlewares: {use}});

    const middleware = use.mock.calls[0][0] as (
      request: {url?: string},
      response: {statusCode: number, setHeader: (name: string, value: string) => void, end: (body: string) => void},
      next: () => void
    ) => void;
    const response = {
      statusCode: 0,
      setHeader: vi.fn(),
      end: vi.fn()
    };
    const next = vi.fn();

    middleware({url: `${WEB_VERSION_RESOURCE_PATH}?cache-bust=1`}, response, next);

    expect(next).not.toHaveBeenCalled();
    expect(response.statusCode).toBe(200);
    expect(response.setHeader).toHaveBeenCalledWith('Content-Type', 'text/plain; charset=utf-8');
    expect(response.setHeader).toHaveBeenCalledWith('Cache-Control', 'no-store');
    expect(response.end).toHaveBeenCalledWith(fullVersion);
  });

  it('requests the absolute same-origin resource and stays quiet for an unchanged version', async() => {
    const fetcher = vi.fn().mockResolvedValue(new Response(fullVersion, {
      headers: {'Content-Type': 'text/plain; charset=utf-8'}
    }));

    await expect(hasWebVersionUpdate(fullVersion, fetcher as unknown as typeof fetch)).resolves.toBe(false);

    expect(fetcher).toHaveBeenCalledWith(
      new URL(WEB_VERSION_RESOURCE_PATH, location.origin),
      {cache: 'no-cache'}
    );
  });

  it('detects a changed full-version string', async() => {
    const fetcher = vi.fn().mockResolvedValue(new Response('2.2 (677)', {
      headers: {'Content-Type': 'text/plain; charset=utf-8'}
    }));

    await expect(hasWebVersionUpdate(fullVersion, fetcher as unknown as typeof fetch)).resolves.toBe(true);
  });

  it('ignores an SPA HTML fallback instead of treating it as version metadata', async() => {
    const fetcher = vi.fn().mockResolvedValue(new Response('<!doctype html>', {
      headers: {'Content-Type': 'text/html; charset=utf-8'}
    }));

    await expect(hasWebVersionUpdate(fullVersion, fetcher as unknown as typeof fetch)).resolves.toBe(false);
  });

  it('does not retain the legacy version poll or writer', () => {
    const sidebarSource = readFileSync('src/components/sidebarLeft/index.ts', 'utf8');
    const versionScriptSource = readFileSync('src/scripts/change_version.js', 'utf8');

    expect(sidebarSource).toContain('hasWebVersionUpdate');
    expect(sidebarSource).not.toMatch(/fetch\(['"]version['"]/);
    expect(versionScriptSource).not.toMatch(/writeFileSync\(['"]\.\/public\/version/);
  });
});
