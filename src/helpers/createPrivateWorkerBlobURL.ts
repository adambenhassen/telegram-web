const STATIC_IMPORT_SPECIFIER = /(\b(?:import|export)\b[^'"\x60;]*?\bfrom\s*|\bimport\s*)(["'])(\/(?!\/)[^"'\x60]+|\.{1,2}\/[^"'\x60]+)\2/g;

export function rewritePrivateWorkerImports(source: string, base: string) {
  return source.replace(STATIC_IMPORT_SPECIFIER, (_match, prefix: string, quote: string, specifier: string) => {
    const path = specifier.startsWith('/') ? specifier.slice(1) : specifier;
    return prefix + quote + new URL(path, base).href + quote;
  });
}

export async function createPrivateWorkerBlobURL(url: string | URL) {
  const response = await fetch(url);
  if(!response.ok) {
    throw new Error(`[MT] unable to load private MTProto worker (${response.status})`);
  }

  let source = await response.text();
  const pathnameSplitted = location.pathname.split('/');
  pathnameSplitted[pathnameSplitted.length - 1] = '';
  const base = location.origin + pathnameSplitted.join('/');
  source = rewritePrivateWorkerImports(source, base);

  return URL.createObjectURL(new Blob([source], {type: 'application/javascript'}));
}
