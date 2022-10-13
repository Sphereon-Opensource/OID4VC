import { fetch } from 'cross-fetch';

export async function post(url: string, body: unknown, bearerToken?: string): Promise<Response> {
  let response = null;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: bearerToken
        ? {
            Authorization: `Bearer ${bearerToken}`,
          }
        : {},
      body: JSON.stringify(body),
    });
    if (response && response.status && response.status < 400) {
      return response;
    }
  } catch (error) {
    throw new Error(`${(error as Error).message}`);
  }

  throw new Error(`${await response.json()}`);
}
