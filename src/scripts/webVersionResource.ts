import type {Plugin} from 'vite';
import {WEB_VERSION_RESOURCE_PATH} from '../lib/webVersion';

export default function webVersionResourcePlugin(): Plugin {
  let versionFull: string;

  return {
    name: 'tweb:web-version-resource',
    configResolved(config) {
      versionFull = config.env.VITE_VERSION_FULL;
    },
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        if(request.url?.split('?')[0] !== WEB_VERSION_RESOURCE_PATH) {
          return next();
        }

        response.statusCode = 200;
        response.setHeader('Content-Type', 'text/plain; charset=utf-8');
        response.setHeader('Cache-Control', 'no-store');
        response.end(versionFull);
      });
    },
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: WEB_VERSION_RESOURCE_PATH.slice(1),
        source: versionFull
      });
    }
  };
}
