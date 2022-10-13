import { BAD_PARAMS } from '../Oidc4vciErrors';
import { DecodeURIAsJsonOpts, EncodeJsonAsURIOpts, IssuanceInitiationRequestPayload, SearchValue } from '../types';

/**
 * @function encodeJsonAsURI encodes a Json object into an URI
 * @param json object
 * @param opts:
 *          - urlTypeProperties: a list of properties which the value is an URL
 *          - arrayTypeProperties: a list of properties which are an array
 */
export function encodeJsonAsURI(json: unknown, opts?: EncodeJsonAsURIOpts): string {
  if (typeof json === 'string') {
    return encodeJsonAsURI(JSON.parse(json));
  }
  const results = [];

  function encodeAndStripWhitespace(key: string) {
    return encodeURIComponent(key.replace(' ', ''));
  }

  for (const [key, value] of Object.entries(json)) {
    if (!value) {
      continue;
    }
    //Skip properties that are not of URL type
    if (!opts?.urlTypeProperties.includes(key)) {
      results.push(`${key}=${value}`);
      continue;
    }
    if (opts.arrayTypeProperties?.includes(key) && Array.isArray(value)) {
      results.push(
        value.map((v) => `${encodeAndStripWhitespace(key)}=${customEncodeURIComponent(v, /\./g)}`).join('&')
      );
      continue;
    }
    const isBool = typeof value == 'boolean';
    const isNumber = typeof value == 'number';
    const isString = typeof value == 'string';
    let encoded;
    if (isBool || isNumber) {
      encoded = `${encodeAndStripWhitespace(key)}=${value}`;
    } else if (isString) {
      encoded = `${encodeAndStripWhitespace(key)}=${customEncodeURIComponent(value, /\./g)}`;
    } else {
      encoded = `${encodeAndStripWhitespace(key)}=${customEncodeURIComponent(JSON.stringify(value), /\./g)}`;
    }
    results.push(encoded);
  }
  return results.join('&');
}

/**
 * @function decodeUriAsJson decodes an URI into a Json object
 * @param uri string
 * @param opts:
 *          - requiredProperties: the required properties
 *          - duplicatedProperties: properties that show up more that once
 */
export function decodeURIAsJson(uri: string, opts?: DecodeURIAsJsonOpts): IssuanceInitiationRequestPayload {
  if (!uri || !opts?.requiredProperties.every((p) => uri.includes(p))) {
    throw new Error(BAD_PARAMS);
  }
  const parsedURI = parseURI(uri, opts?.duplicatedProperties);
  return decodeJsonProperty(parsedURI);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function decodeJsonProperty(parts: any): any {
  const json: unknown = {};
  for (const key in parts) {
    const value = parts[key];
    if (!value) {
      continue;
    }
    if (Array.isArray(value)) {
      if (value.length > 1) {
        json[decodeURIComponent(key)] = value.map((v) => decodeURIComponent(v));
      } else {
        json[decodeURIComponent(key)] = decodeURIComponent(value[0]);
      }
    }
    const isBool = typeof value == 'boolean';
    const isNumber = typeof value == 'number';
    const isString = typeof value == 'string';
    if (isBool || isNumber) {
      json[decodeURIComponent(key)] = value;
    } else if (isString) {
      const decoded = decodeURIComponent(value);
      if (decoded.startsWith('{') && decoded.endsWith('}')) {
        json[decodeURIComponent(key)] = JSON.parse(decoded);
      } else {
        json[decodeURIComponent(key)] = decoded;
      }
    }
  }
  return json;
}

/**
 * @function parseURI into a Json object
 * @param uri string
 * @param duplicated array of string containing duplicated uri keys
 */
export function parseURI(uri: string, duplicated?: string[]): unknown {
  const json: unknown = {};
  const dict = uri.split('&');
  for (const entry of dict) {
    const pair = entry.split('=');
    if (duplicated?.includes(pair[0])) {
      if (json[pair[0]] !== undefined) {
        json[pair[0]].push(pair[1]);
      } else {
        json[pair[0]] = [pair[1]];
      }
      continue;
    }
    json[pair[0]] = pair[1];
  }
  return json;
}

/**
 * @function customEncodeURIComponent is used to encode chars that are not encoded by default
 * @param searchValue The pattern/regexp to find the char(s) to be encoded
 * @param uriComponent query string
 */
export function customEncodeURIComponent(uriComponent: string, searchValue: SearchValue): string {
  // -_.!~*'() are not escaped because they are considered safe.
  // Add them to the regex as you need
  return encodeURIComponent(uriComponent).replace(searchValue, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}
