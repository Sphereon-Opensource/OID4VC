import { fetch } from 'cross-fetch';
import Debug from 'debug';

import { Encoding, OpenIDResponse } from '../types';

const debug = Debug('sphereon:openid4vci:http');

export const getJson = async <T>(
  URL: string,
  opts?: {
    bearerToken?: (() => Promise<string>) | string;
    contentType?: string;
    accept?: string;
    customHeaders?: Record<string, string>;
    exceptionOnHttpErrorStatus?: boolean;
  },
): Promise<OpenIDResponse<T>> => {
  return await openIdFetch(URL, undefined, { method: 'GET', ...opts });
};

export const formPost = async <T>(
  url: string,
  body: BodyInit,
  opts?: {
    bearerToken?: (() => Promise<string>) | string;
    contentType?: string;
    accept?: string;
    customHeaders?: Record<string, string>;
    exceptionOnHttpErrorStatus?: boolean;
  },
): Promise<OpenIDResponse<T>> => {
  return await post(url, body, opts?.contentType ? { ...opts } : { contentType: Encoding.FORM_URL_ENCODED, ...opts });
};

export const post = async <T>(
  url: string,
  body?: BodyInit,
  opts?: {
    bearerToken?: (() => Promise<string>) | string;
    contentType?: string;
    accept?: string;
    customHeaders?: Record<string, string>;
    exceptionOnHttpErrorStatus?: boolean;
  },
): Promise<OpenIDResponse<T>> => {
  return await openIdFetch(url, body, { method: 'POST', ...opts });
};

const openIdFetch = async <T>(
  url: string,
  body?: BodyInit,
  opts?: {
    method?: string;
    bearerToken?: (() => Promise<string>) | string;
    contentType?: string;
    accept?: string;
    customHeaders?: Record<string, string>;
    exceptionOnHttpErrorStatus?: boolean;
  },
): Promise<OpenIDResponse<T>> => {
  const headers: Record<string, string> = opts?.customHeaders ?? {};
  if (opts?.bearerToken) {
    headers['Authorization'] = `Bearer ${typeof opts.bearerToken === 'function' ? await opts.bearerToken() : opts.bearerToken}`;
  }
  const method = opts?.method ? opts.method : body ? 'POST' : 'GET';
  const accept = opts?.accept ? opts.accept : 'application/json';
  headers['Accept'] = accept;
  if (headers['Content-Type']) {
    if (opts?.contentType && opts.contentType !== headers['Content-Type']) {
      throw Error(
        `Mismatch in content-types from custom headers (${headers['Content-Type']}) and supplied content type option (${opts.contentType})`,
      );
    }
  } else {
    if (opts?.contentType) {
      headers['Content-Type'] = opts.contentType;
    } else if (method !== 'GET') {
      headers['Content-Type'] = 'application/json';
    }
  }

  const payload: RequestInit = {
    method,
    headers,
    body,
  };

  debug(`START fetching url: ${url}`);
  if (body) {
    debug(`Body:\r\n${typeof body == 'string' ? body : JSON.stringify(body)}`);
  }
  debug(`Headers:\r\n${JSON.stringify(payload.headers)}`);
  const origResponse = await fetch(url, payload);
  const isJSONResponse = accept === 'application/json' || origResponse.headers.get('Content-Type') === 'application/json';
  const success = origResponse && origResponse.status >= 200 && origResponse.status < 400;
  const responseText = await origResponse.text();
  const responseBody = isJSONResponse && responseText.includes('{') ? JSON.parse(responseText) : responseText;

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
    '^(https?:\\/\\/)' + // validate protocol
      '((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|' + // validate domain name
      '((localhost))|' + // validate OR localhost
      '((\\d{1,3}\\.){3}\\d{1,3}))' + // validate OR ip (v4) address
      '(\\:\\d+)?(\\/[-a-z\\d%_.~+:]*)*' + // validate port and path
      '(\\?[;&a-z\\d%_.~+=-]*)?' + // validate query string
      '(\\#[-a-z\\d_]*)?$', // validate fragment locator
    'i',
  );
  return urlPattern.test(url);
};

export const trimBoth = (value: string, trim: string): string => {
  return trimEnd(trimStart(value, trim), trim);
};

export const trimEnd = (value: string, trim: string): string => {
  return value.endsWith(trim) ? value.substring(0, value.length - trim.length) : value;
};

export const trimStart = (value: string, trim: string): string => {
  return value.startsWith(trim) ? value.substring(trim.length) : value;
};

export const adjustUrl = <T extends string | URL>(
  urlOrPath: T,
  opts?: {
    stripSlashEnd?: boolean;
    stripSlashStart?: boolean;
    prepend?: string;
    append?: string;
  },
): T => {
  let url = typeof urlOrPath === 'object' ? urlOrPath.toString() : (urlOrPath as string);
  if (opts?.append) {
    url = trimEnd(url, '/') + '/' + trimStart(opts.append, '/');
  }
  if (opts?.prepend) {
    if (opts.prepend.includes('://')) {
      // includes domain/hostname
      if (!url.startsWith(opts.prepend)) {
        url = trimEnd(opts.prepend, '/') + '/' + trimStart(url, '/');
      }
    } else {
      // path only for prepend
      let host = '';
      let path = url;
      if (url.includes('://')) {
        // includes domain/hostname
        host = new URL(url).host;
        path = new URL(url).pathname;
      }
      if (!path.startsWith(opts.prepend)) {
        if (host && host !== '') {
          url = trimEnd(host, '/');
        }
        url += trimEnd(url, '/') + '/' + trimBoth(opts.prepend, '/') + '/' + trimStart(path, '/');
      }
    }
  }
  if (opts?.stripSlashStart) {
    url = trimStart(url, '/');
  }
  if (opts?.stripSlashEnd) {
    url = trimEnd(url, '/');
  }

  if (typeof urlOrPath === 'string') {
    return url as T;
  }
  return new URL(url) as T;
};
