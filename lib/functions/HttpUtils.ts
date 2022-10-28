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
      console.log(`Well-knonw response: ${JSON.stringify(json, null, 2)}`);
      return json as T;
    } else if (response.status === 404) {
      throw new NotFoundError(`URL ${URL} was not found`);
    } else {
      message = `${response.status}:${response.statusText}, ${await response.text()}`;
    }
  }
  console.log(`Well-knonw error: ${message}`);
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

  const headers = opts?.customHeaders ? opts.customHeaders : [];

  if (opts?.bearerToken) {
    headers['Authorization'] = `Bearer ${opts.bearerToken}`;
  }
  headers['Content-Type'] = opts?.contentType ? opts.contentType : 'application/json';
  headers['Accept'] = opts?.accept ? opts.accept : 'application/json';

  const payload: RequestInit = {
    method: 'POST',
    headers,
    body,
  };

  try {
    // TODO: Remove the console.logs!
    console.log(`START fetching url: ${url}`);
    console.log(`with Headers: ${JSON.stringify(payload.headers)}`);
    console.log(`with body: ${body}`);
    // console.log(`with payload: ${JSON.stringify(payload)}`);
    const response = await fetch(url, payload);
    if (response && response.status >= 200 && response.status < 400) {
      const logResponse = response.clone();
      try {
        // console.log(`Success response with status ${logResponse.status}. Headers: ${JSON.stringify(logResponse.headers)}`);
        console.log(`Success response: ${JSON.stringify(await logResponse.json(), null, 2)}`);
      } catch (jsonerror) {
        console.log('success response did throw error on serialization: ' + jsonerror.message);
        console.log(`Success response: ${JSON.stringify(await logResponse.text(), null, 2)}`);
      }
      console.log(`END fetching url: ${url}`);
      return response;
    } else {
      if (response) {
        const logResponse = response.clone();
        console.log(
          `Response with status ${logResponse.status} and status text ${logResponse.statusText} with headers ${JSON.stringify(logResponse.headers)})}`
        );
        try {
          message = `${logResponse.status}:${logResponse.statusText}, ${JSON.stringify(await logResponse.json())}`;
        } catch (jsonerror) {
          console.log(`accessing error body as json failed. Using text next.`);
          message = `${logResponse.status}:${logResponse.statusText}, ${await logResponse.text()}`;
        }
      } else {
        console.log(`No response received for ${url}`);
      }
    }
  } catch (error) {
    const err = error as Error;
    console.log(`Error: ${JSON.stringify(err.stack)} ${error.message}`);
    console.log(`END fetching url: ${url}`);
    throw new Error(`${(error as Error).message}`);
  }

  console.log(`unexpected Error: ${JSON.stringify(message)}`);
  console.log(`END fetching url: ${url}`);
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
