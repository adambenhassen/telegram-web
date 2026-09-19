export async function createPrivateWorkerBlobURL(url: string | URL) {
  const response = await fetch(url);
  if(!response.ok) {
    throw new Error(`[MT] unable to load private MTProto worker (${response.status})`);
  }

  let source = await response.text();
  const pathnameSplitted = location.pathname.split('/');
  pathnameSplitted[pathnameSplitted.length - 1] = '';
  const base = location.origin + pathnameSplitted.join('/');
  source = source.replace(/(import (?:.+? from )?['"])\//g, '$1' + base);

  return URL.createObjectURL(new Blob([source], {type: 'application/javascript'}));
}
