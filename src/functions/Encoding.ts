import { IssuanceInitiationRequestPayload, SearchValue } from '../types/IssuanceInitiationRequestTypes';
import { BAD_PARAMS } from '../types/Oidc4vciErrors';

/**
 * @function encodeOidc4vciJsonAsURI encodes a Json object into an URI
 * @param json object of type IssuanceInitiationRequestPayload
 */
export function encodeOidc4vciJsonAsURI(json: IssuanceInitiationRequestPayload): string {
  if (typeof json === 'string') {
    return encodeOidc4vciJsonAsURI(JSON.parse(json));
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
    if (!['issuer', 'credential_type'].includes(key)) {
      results.push(`${key}=${value}`);
      continue;
    }
    if (key === 'credential_type') {
      results.push(value.map((v) => `${encodeAndStripWhitespace(key)}=${encodeOidc4vciURIComponent(v, /\./g)}`).join('&'));
      continue;
    }
    const isBool = typeof value == 'boolean';
    const isNumber = typeof value == 'number';
    const isString = typeof value == 'string';
    let encoded;
    if (isBool || isNumber) {
      encoded = `${encodeAndStripWhitespace(key)}=${value}`;
    } else if (isString) {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeOidc4vciURIComponent(value, /\./g)}`;
    } else {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeOidc4vciURIComponent(JSON.stringify(value), /\./g)}`;
    }
    results.push(encoded);
  }
  return results.join('&');
}

/**
 * @function decodeOidc4vciUriAsJson decodes an URI into a Json object
 * @param uri string
 */
export function decodeOidc4vciURIAsJson(uri: string): IssuanceInitiationRequestPayload {
  if (!uri || !uri.includes('issuer') || !uri.includes('credential_type')) {
    throw new Error(BAD_PARAMS);
  }
  const parsedURI = parseURI(uri, ['credential_type']);
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
      json[decodeURIComponent(key)] = value.map((v) => decodeURIComponent(v));
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
 * @function encodeOidc4vciURIComponent is used to encode chars that are not encoded by default
 * @param searchValue The pattern/regexp to find the char(s) to be encoded
 * @param uriComponent query string
 */
export function encodeOidc4vciURIComponent(uriComponent: string, searchValue: SearchValue): string {
  // -_.!~*'() are not escaped because they are considered safe.
  // Add them to the regex as you need
  return encodeURIComponent(uriComponent).replace(searchValue, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}
