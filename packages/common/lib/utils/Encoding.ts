import { parse } from 'querystring';

import jwt_decode from 'jwt-decode';

import { BAD_PARAMS, JWTHeader } from '../index';

export function getKidFromJWT(jwt: string): string {
  const header: JWTHeader = jwt_decode(jwt);
  return header.kid as string;
}

export function decodeUriAsJson(uri: string) {
  if (!uri) {
    throw new Error(BAD_PARAMS);
  }
  const queryString = uri.replace(/^([a-zA-Z-_]+:\/\/[?]?)/g, '');
  if (!queryString) {
    throw new Error(BAD_PARAMS);
  }
  const parts = parse(queryString);

  const json = {};
  for (const key in parts) {
    const value = parts[key];
    if (!value) {
      continue;
    }
    const isBool = typeof value === 'boolean';
    const isNumber = typeof value === 'number';
    const isString = typeof value == 'string';

    if (isBool || isNumber) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      json[decodeURIComponent(key)] = value;
    } else if (isString) {
      const decoded = decodeURIComponent(value);
      if (decoded.startsWith('{') && decoded.endsWith('}')) {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        json[decodeURIComponent(key)] = JSON.parse(decoded);
      } else {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        json[decodeURIComponent(key)] = decoded;
      }
    }
  }
  return json;
}

export function encodeJsonAsURI(json: unknown): string {
  if (typeof json === 'string') {
    return encodeJsonAsURI(JSON.parse(json));
  }

  const results: string[] = [];

  function encodeAndStripWhitespace(key: string): string {
    return encodeURIComponent(key.replace(' ', ''));
  }

  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  for (const [key, value] of Object.entries(json)) {
    if (!value) {
      continue;
    }
    const isBool = typeof value == 'boolean';
    const isNumber = typeof value == 'number';
    const isString = typeof value == 'string';
    let encoded;
    if (isBool || isNumber) {
      encoded = `${encodeAndStripWhitespace(key)}=${value}`;
    } else if (isString) {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeURIComponent(value)}`;
    } else {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeURIComponent(JSON.stringify(value))}`;
    }
    results.push(encoded);
  }
  return results.join('&');
}
