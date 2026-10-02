export const WEB_VERSION_RESOURCE_PATH = '/.well-known/telegram-web/version.txt';

export async function hasWebVersionUpdate(currentVersion: string, fetcher: typeof fetch = fetch) {
  const response = await fetcher(new URL(WEB_VERSION_RESOURCE_PATH, location.origin), {cache: 'no-cache'});
  const contentType = response.headers.get('content-type');
  if(response.status !== 200 || !response.ok || !contentType || !/^text\/plain(?:;|$)/i.test(contentType)) {
    return false;
  }

  return (await response.text()) !== currentVersion;
}
