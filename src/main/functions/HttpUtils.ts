import { fetch } from 'cross-fetch';

import { CredentialRequest } from '../types';

export async function postWithBearerToken(url: string, body: CredentialRequest, bearerToken: string): Promise<Response> {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${bearerToken}`,
      },
      body: JSON.stringify(body),
    });
    if (!response || !response.status || response.status >= 400) {
      throw new Error(`${await response.json()}`);
    }
    return response;
  } catch (error) {
    throw new Error(`${(error as Error).message}`);
  }
}
