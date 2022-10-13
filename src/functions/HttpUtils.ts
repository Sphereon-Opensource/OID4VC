import { fetch } from 'cross-fetch';

export async function post(url: string, body: unknown, bearerToken?: string): Promise<Response> {
  try {
    const payload = {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bearerToken}`,
      },
      body: JSON.stringify(body),
    };
    const response = await fetch(url, payload);
    if (!response || !response.status || (response.status !== 200 && response.status !== 201)) {
      throw new Error(`${'RESPONSE_STATUS_UNEXPECTED'} ${response.status}:${response.statusText}, ${await response.text()}`);
    }
    return response;
  } catch (error) {
    throw new Error(`${(error as Error).message}`);
  }
}

export function isValidURL(url: string): boolean {
  const urlPattern = new RegExp(
    '^(https:\\/\\/)?' + // validate protocol
      '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|' + // validate domain name
      '((\\d{1,3}\\.){3}\\d{1,3}))' + // validate OR ip (v4) address
      '(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*' + // validate port and path
      '(\\?[;&a-z\\d%_.~+=-]*)?' + // validate query string
      '(\\#[-a-z\\d_]*)?$',
    'i'
  ); // validate fragment locator
  return !!urlPattern.test(url);
}
