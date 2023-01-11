import { fetch } from 'cross-fetch';
import Debug from 'debug';

import { Encoding, OpenIDResponse } from '../types';

const debug = Debug('sphereon:openid4vci:http');

export const getJson = async <T>(
  URL: string,
  opts?: { bearerToken?: string; contentType?: string; accept?: string; customHeaders?: HeadersInit; exceptionOnHttpErrorStatus?: boolean }
): Promise<OpenIDResponse<T>> => {
  return await openIdFetch(URL, undefined, { method: 'GET', ...opts });
};

export const formPost = async <T>(
  url: string,
  body: BodyInit,
  opts?: { bearerToken?: string; contentType?: string; accept?: string; customHeaders?: HeadersInit; exceptionOnHttpErrorStatus?: boolean }
): Promise<OpenIDResponse<T>> => {
  return await post(url, body, opts?.contentType ? { ...opts } : { contentType: Encoding.FORM_URL_ENCODED, ...opts });
};

export const post = async <T>(
  url: string,
  body?: BodyInit,
  opts?: { bearerToken?: string; contentType?: string; accept?: string; customHeaders?: HeadersInit; exceptionOnHttpErrorStatus?: boolean }
): Promise<OpenIDResponse<T>> => {
  return await openIdFetch(url, body, { method: 'POST', ...opts });
};

const openIdFetch = async <T>(
  url: string,
  body?: BodyInit,
  opts?: {
    method?: string;
    bearerToken?: string;
    contentType?: string;
    accept?: string;
    customHeaders?: HeadersInit;
    exceptionOnHttpErrorStatus?: boolean;
  }
): Promise<OpenIDResponse<T>> => {
  const headers = opts?.customHeaders ? opts.customHeaders : {};
  if (opts?.bearerToken) {
    headers['Authorization'] = `Bearer ${opts.bearerToken}`;
  }
  const method = opts?.method ? opts.method : body ? 'POST' : 'GET';
  const accept = opts?.accept ? opts.accept : 'application/json';
  headers['Content-Type'] = opts?.contentType ? opts.contentType : method !== 'GET' ? 'application/json' : undefined;
  headers['Accept'] = accept;

  const payload: RequestInit = {
    method,
    headers,
    body,
  };

  debug(`START fetching url: ${url}`);
  if (body) {
    debug(`Body:\r\n${JSON.stringify(body)}`);
  }
  debug(`Headers:\r\n${JSON.stringify(payload.headers)}`);
  const origResponse = await fetch(url, payload);
  const isJSONResponse = accept === 'application/json' || origResponse.headers['Content-Type'] === 'application/json';
  const success = origResponse && origResponse.status >= 200 && origResponse.status < 400;
  const responseText = await origResponse.text();
  const responseBody = isJSONResponse ? JSON.parse(responseText) : responseText;

  debug(`${success ? 'success' : 'error'} status: ${origResponse.status}, body:\r\n${JSON.stringify(responseBody)}`);
  if (!success && opts?.exceptionOnHttpErrorStatus) {
    const error = JSON.stringify(responseBody);
    throw new Error(error === '{}' ? '{"error": "not found"}' : error);
  }
  debug(`END fetching url: ${url}`);

  return {
    origResponse,
    successBody: success ? responseBody : undefined,
    errorBody: !success ? responseBody : undefined,
  };
};

export const isValidURL = (url: string): boolean => {
  const urlPattern = new RegExp(
    '^(https?:\\/\\/)?' + // validate protocol
      '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|' + // validate domain name
      '((\\d{1,3}\\.){3}\\d{1,3}))' + // validate OR ip (v4) address
      '(\\:\\d+)?(\\/[-a-z\\d%_.~+:]*)*' + // validate port and path
      '(\\?[;&a-z\\d%_.~+=-]*)?' + // validate query string
      '(\\#[-a-z\\d_]*)?$', // validate fragment locator
    'i'
  );
  return !!urlPattern.test(url);
};
