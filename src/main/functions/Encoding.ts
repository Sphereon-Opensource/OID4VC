import { IssuanceInitiationRequestPayload } from '../types';
import { BAD_PARAMS } from '../Oidc4vciErrors';

export function encodeJsonAsURI(json: IssuanceInitiationRequestPayload[] | IssuanceInitiationRequestPayload) {
  if (!Array.isArray(json)) {
    return encodeJsonObjectAsURI(json);
  }
  return json.map((j) => encodeJsonObjectAsURI(j)).join('&');
}

function encodeJsonObjectAsURI(json: IssuanceInitiationRequestPayload) {
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

export function decodeUriAsJson(uri: string) {
  if (!uri || !uri.includes('issuer') || !uri.includes('credential_type')) {
    throw new Error(BAD_PARAMS);
  }
  const jsonArray = parseURI(uri);
  const result = jsonArray.map((o) => decodeJsonProperty(o));
  return result.length < 2 ? result[0] : result;
}

function decodeJsonProperty(parts: IssuanceInitiationRequestPayload) {
  const json = {};
  for (const key in parts) {
    const value = parts[key];
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
