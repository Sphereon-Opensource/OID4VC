import { fetch } from 'cross-fetch';

import { Encoding } from '../types';

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
  }
}

export async function getJson<T>(URL: string): Promise<T> {
  let message = '';

  // TODO: Remove console.logs
  console.log(`Well-known URL: URL`);
  const response = await fetch(URL);
  if (!response) {
    message = 'no response returned';
  } else {
    if (response.status && response.status < 400) {
      const json = await response.json();
      // console.log(`Well-knonw response: ${JSON.stringify(json, null, 2)}`);
      return json as T;
    } else if (response.status === 404) {
      throw new NotFoundError(`URL ${URL} was not found`);
    } else {
      message = `${response.status}:${response.statusText}, ${await response.text()}`;
    }
  }
  console.log(`Well-known error: ${message}`);
  throw new Error('error: ' + message);
}

export async function formPost(
  url: string,
  body: BodyInit,
  opts?: { bearerToken?: string; contentType?: string; accept?: string; customHeaders?: HeadersInit }
): Promise<Response> {
  return await post(url, body, opts?.contentType ? { ...opts } : { contentType: Encoding.FORM_URL_ENCODED, ...opts });
}

export async function post(
  url: string,
  body: BodyInit,
  opts?: { bearerToken?: string; contentType?: string; accept?: string; customHeaders?: HeadersInit }
): Promise<Response> {
  let message = '';
  try {
    const payload: RequestInit = {
      method: 'POST',
      body,
    };
    const headers = opts?.customHeaders ? { ...opts.customHeaders, ...payload.headers } : { ...payload.headers };

    if (opts?.bearerToken) {
      headers['Authorization'] = `Bearer ${opts.bearerToken}`;
    }
    if (opts?.contentType) {
      headers['Content-Type'] = opts.contentType;
    }
    headers['Accept'] = opts?.accept ? opts.accept : 'application/json';
    payload.headers = headers;

    // TODO: Remove the console.logs!
    console.log(`fetching url: ${url}`);
    console.log(`with payload: ${JSON.stringify(payload, null, 2)}`);
    const response = await fetch(url, payload);
    if (response && response.status && response.status < 400) {
      console.log(`response: ${JSON.stringify(response, null, 2)}`);
      return response;
    } else {
      if (response) {
        message = `${response.status}:${response.statusText}, ${await response.text()}`;
      }
    }
  } catch (error) {
    console.log(`Error: ${error} ${error.message}`);
    throw new Error(`${(error as Error).message}`);
  }

  console.log(`unexpected Error: ${message}`);
  throw new Error('unexpected error: ' + message);
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
