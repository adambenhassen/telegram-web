const STATIC_IMPORT_SPECIFIER = /(\b(?:import|export)\b[^'"\x60;]*?\bfrom\s*|\bimport\s*)(["'])(\/(?!\/)[^"'\x60]+|\.{1,2}\/[^"'\x60]+)\2/g;
const DYNAMIC_IMPORT_SPECIFIER = /(\bimport\s*\(\s*)(["'\x60])(\/(?!\/)[^"'\x60]+|\.{1,2}\/[^"'\x60]+)\2(\s*\))/g;

function resolvePrivateWorkerSpecifier(specifier: string, base: string) {
  const path = specifier.startsWith('/') ? specifier.slice(1) : specifier;
  const expressionStart = path.indexOf('$' + '{');
  if(expressionStart >= 0) {
    return new URL(path.slice(0, expressionStart), base).href + path.slice(expressionStart);
  }
  return new URL(path, base).href;
}

export function rewritePrivateWorkerImports(source: string, base: string) {
  return source
    .replace(STATIC_IMPORT_SPECIFIER, (_match, prefix: string, quote: string, specifier: string) =>
      prefix + quote + resolvePrivateWorkerSpecifier(specifier, base) + quote
    )
    .replace(DYNAMIC_IMPORT_SPECIFIER, (_match, prefix: string, quote: string, specifier: string, suffix: string) =>
      prefix + quote + resolvePrivateWorkerSpecifier(specifier, base) + quote + suffix
    );
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
