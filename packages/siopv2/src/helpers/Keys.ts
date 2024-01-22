// import { keyUtils as ed25519KeyUtils } from '@transmute/did-key-ed25519';
// import { ec as EC } from 'elliptic';
import * as u8a from 'uint8arrays';

import { JWK } from '../types';

const ED25519_DID_KEY = 'did:key:z6Mk';

export const isEd25519DidKeyMethod = (did?: string) => {
  return did && did.includes(ED25519_DID_KEY);
};

/*
export const isEd25519JWK = (jwk: JWK): boolean => {
  return jwk && !!jwk.crv && jwk.crv === KeyCurve.ED25519;
};

export const getBase58PrivateKeyFromHexPrivateKey = (hexPrivateKey: string): string => {
  return bs58.encode(Buffer.from(hexPrivateKey, 'hex'));
};

export const getPublicED25519JWKFromHexPrivateKey = (hexPrivateKey: string, kid?: string): JWK => {
  const ec = new EC('ed25519');
  const privKey = ec.keyFromPrivate(hexPrivateKey);
  const pubPoint = privKey.getPublic();

  return toJWK(kid, KeyCurve.ED25519, pubPoint);
};

const getPublicSECP256k1JWKFromHexPrivateKey = (hexPrivateKey: string, kid: string) => {
  const ec = new EC('secp256k1');
  const privKey = ec.keyFromPrivate(hexPrivateKey.replace('0x', ''), 'hex');
  const pubPoint = privKey.getPublic();
  return toJWK(kid, KeyCurve.SECP256k1, pubPoint);
};

export const getPublicJWKFromHexPrivateKey = (hexPrivateKey: string, kid?: string, did?: string): JWK => {
  if (isEd25519DidKeyMethod(did)) {
    return getPublicED25519JWKFromHexPrivateKey(hexPrivateKey, kid);
  }
  return getPublicSECP256k1JWKFromHexPrivateKey(hexPrivateKey, kid);
};

const toJWK = (kid: string, crv: KeyCurve, pubPoint: EC.BN) => {
  return {
    kid,
    kty: KeyType.EC,
    crv: crv,
    x: base64url.toBase64(pubPoint.getX().toArrayLike(Buffer)),
    y: base64url.toBase64(pubPoint.getY().toArrayLike(Buffer))
  };
};

// from fingerprintFromPublicKey function in @transmute/Ed25519KeyPair
const getThumbprintFromJwkDIDKeyImpl = (jwk: JWK): string => {
  // ed25519 cryptonyms are multicodec encoded values, specifically:
  // (multicodec ed25519-pub 0xed01 + key bytes)
  const pubkeyBytes = base64url.toBuffer(jwk.x);
  const buffer = new Uint8Array(2 + pubkeyBytes.length);
  buffer[0] = 0xed;
  buffer[1] = 0x01;
  buffer.set(pubkeyBytes, 2);

  // prefix with `z` to indicate multi-base encodingFormat

  return base64url.encode(`z${u8a.toString(buffer, 'base58btc')}`);
};

export const getThumbprintFromJwk = async (jwk: JWK, did: string): Promise<string> => {
  if (isEd25519DidKeyMethod(did)) {
    return getThumbprintFromJwkDIDKeyImpl(jwk);
  } else {
    return await calculateJwkThumbprint(jwk, 'sha256');
  }
};

export const getThumbprint = async (hexPrivateKey: string, did: string): Promise<string> => {
  return await getThumbprintFromJwk(
    isEd25519DidKeyMethod(did) ? getPublicED25519JWKFromHexPrivateKey(hexPrivateKey) : getPublicJWKFromHexPrivateKey(hexPrivateKey),
    did
  );
};
*/

const check = (value: string | undefined, description: string) => {
  if (!value) {
    throw Error(`${description} missing or invalid`);
  }
};

async function calculateJwkThumbprint(jwk: JWK, digestAlgorithm?: 'sha256' | 'sha384' | 'sha512'): Promise<string> {
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
  const data = u8a.fromString(JSON.stringify(components), 'utf-8');
  return u8a.toString(await digest(algorithm, data), 'base64url');
}

const digest = async (algorithm: 'sha256' | 'sha384' | 'sha512', data: Uint8Array) => {
  const subtleDigest = `SHA-${algorithm.slice(-3)}`;
  return new Uint8Array(await crypto.subtle.digest(subtleDigest, data));
};

export async function calculateJwkThumbprintUri(jwk: JWK, digestAlgorithm?: 'sha256' | 'sha384' | 'sha512'): Promise<string> {
  digestAlgorithm !== null && digestAlgorithm !== void 0 ? digestAlgorithm : (digestAlgorithm = 'sha256');
  const thumbprint = await calculateJwkThumbprint(jwk, digestAlgorithm);
  return `urn:ietf:params:oauth:jwk-thumbprint:sha-${digestAlgorithm.slice(-3)}:${thumbprint}`;
}
