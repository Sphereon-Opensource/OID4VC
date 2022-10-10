import { IssuanceInitiationRequestParams } from '../types/IssuanceInitiationRequestTypes';
import { BAD_PARAMS } from '../types/Oidc4vciErrors';

export function encodeJsonAsURI(json: IssuanceInitiationRequestParams[] | IssuanceInitiationRequestParams) {
  if (!Array.isArray(json)) {
    return encodeJsonObjectAsURI(json);
  }
  return json.map((j) => encodeJsonObjectAsURI(j)).join('&');
}

export function encodeJsonObjectAsURI(json: IssuanceInitiationRequestParams) {
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
  const parts = new URLSearchParams(uri);
  const entries = Array.from(parts.entries());
  const jsonArray = [];
  let json: unknown = {};
  for (const [key, value] of entries) {
    if (Object.prototype.hasOwnProperty.call(json, key)) {
      jsonArray.push(json);
      json = {};
    }
    json[key] = value;
  }
  jsonArray.push(json);
  const result = jsonArray.map((o) => decodeJsonProperty(o));
  return result.length < 2 ? result[0] : result;
}

export function decodeJsonProperty(parts: IssuanceInitiationRequestParams) {
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
