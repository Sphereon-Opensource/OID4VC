import { toString } from 'uint8arrays';

import { defaultHasher } from '../hasher';
import { DigestAlgorithm } from '../types';

import { JWK } from './Jwk.types';

const check = (value: unknown, description: string) => {
  if (typeof value !== 'string' || !value) {
    throw Error(`${description} missing or invalid`);
  }
};

export async function calculateJwkThumbprint(jwk: JWK, digestAlgorithm?: DigestAlgorithm): Promise<string> {
  if (!jwk || typeof jwk !== 'object') {
    throw new TypeError('JWK must be an object');
  }
  const algorithm = digestAlgorithm ?? 'sha256';
  if (algorithm !== 'sha256' && algorithm !== 'sha384' && algorithm !== 'sha512') {
    throw new TypeError('digestAlgorithm must one of "sha256", "sha384", or "sha512"');
  }
  let components;
  switch (jwk.kty) {
    case 'EC':
      check(jwk.crv, '"crv" (Curve) Parameter');
      check(jwk.x, '"x" (X Coordinate) Parameter');
      check(jwk.y, '"y" (Y Coordinate) Parameter');
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
      break;
    case 'OKP':
      check(jwk.crv, '"crv" (Subtype of Key Pair) Parameter');
      check(jwk.x, '"x" (Public Key) Parameter');
      components = { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
      break;
    case 'RSA':
      check(jwk.e, '"e" (Exponent) Parameter');
      check(jwk.n, '"n" (Modulus) Parameter');
      components = { e: jwk.e, kty: jwk.kty, n: jwk.n };
      break;
    case 'oct':
      check(jwk.k, '"k" (Key Value) Parameter');
      components = { k: jwk.k, kty: jwk.kty };
      break;
    default:
      throw Error('"kty" (Key Type) Parameter missing or unsupported');
  }
  return toString(defaultHasher(JSON.stringify(components), algorithm), 'base64url');
}

export async function getDigestAlgorithmFromJwkThumbprintUri(uri: string): Promise<DigestAlgorithm> {
  const match = uri.match(/^urn:ietf:params:oauth:jwk-thumbprint:sha-(\w+):/);
  if (!match) {
    throw new Error(`Invalid JWK thumbprint URI structure ${uri}`);
  }
  const algorithm = `sha${match[1]}` as DigestAlgorithm;
  if (algorithm !== 'sha256' && algorithm !== 'sha384' && algorithm !== 'sha512') {
    throw new Error(`Invalid JWK thumbprint URI digest algorithm ${uri}`);
  }
  return algorithm;
}

export async function calculateJwkThumbprintUri(jwk: JWK, digestAlgorithm: DigestAlgorithm = 'sha256'): Promise<string> {
  const thumbprint = await calculateJwkThumbprint(jwk, digestAlgorithm);
  return `urn:ietf:params:oauth:jwk-thumbprint:sha-${digestAlgorithm.slice(-3)}:${thumbprint}`;
}
