import { BAD_PARAMS } from '../types';

/**
 * @function encodeJsonAsURI encodes a Json object into an URI
 * @param json object or array of type IssuanceInitiationRequestPayload
 */
export function encodeJsonAsURI(json: unknown[] | unknown) {
  if (!Array.isArray(json)) {
    return encodeJsonObjectAsURI(json);
  }
  return json.map((j) => encodeJsonObjectAsURI(j)).join('&');
}

function encodeJsonObjectAsURI(json: unknown) {
  if (typeof json === 'string') {
    return encodeJsonObjectAsURI(JSON.parse(json));
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
 * @function decodeUriAsJson decodes an URI into a Json object
 * @param uri string
 */
export function decodeURIAsJson(uri: string) {
  if (!uri || !uri.includes('issuer') || !uri.includes('credential_type')) {
    throw new Error(BAD_PARAMS);
  }
  const jsonArray = parseURI(uri);
  const result = jsonArray.map((o) => decodeJsonProperty(o));
  return result.length < 2 ? result[0] : result;
}

function decodeJsonProperty(parts: unknown) {
  const json = {};
  for (const [key, value] of Object.entries(parts)) {
    if (!value) {
      continue;
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
 * @function parseURI parses the URI replacing special characters
 * @param uri string
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function parseURI(uri: string) {
  const jsonArray = [];
  let json: unknown = {};
  const dict = uri.split('&');
  for (const entry of dict) {
    const pair = entry.split('=');
    if (Object.prototype.hasOwnProperty.call(json, pair[0])) {
      jsonArray.push(json);
      json = {};
    }
    json[pair[0]] = pair[1];
  }
  jsonArray.push(json);
  return jsonArray;
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
