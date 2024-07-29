import { JWK, JwtHeader, JwtPayload, SigningAlgo } from '..';

import { JwtProtectionMethod, JwtType } from './jwtUtils';

export interface JwtVerifierBase {
  type: JwtType;
  method: JwtProtectionMethod;
}

export interface DidJwtVerifier extends JwtVerifierBase {
  method: 'did';

  alg: SigningAlgo | string;
  didUrl: string;
}

export interface X5cJwtVerifier extends JwtVerifierBase {
  method: 'x5c';

  alg: SigningAlgo | string;

  /**
   *
   * Array of base64-encoded certificate strings in the DER-format.
   *
   * The certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate.
   */
  x5c: Array<string>;

  /**
   * The jwt issuer
   */
  issuer: string;
}

export interface OpenIdFederationJwtVerifier extends JwtVerifierBase {
  method: 'openid-federation';

  /**
   * The OpenId federation Entity
   */
  entityId: string;
}

export interface JwkJwtVerifier extends JwtVerifierBase {
  method: 'jwk';
  alg: SigningAlgo | string;

  jwk: JWK;
}

export interface CustomJwtVerifier extends JwtVerifierBase {
  method: 'custom';
}

export type JwtVerifier = DidJwtVerifier | X5cJwtVerifier | CustomJwtVerifier | JwkJwtVerifier | OpenIdFederationJwtVerifier;

export const getDidJwtVerifier = (jwt: { header: JwtHeader; payload: JwtPayload }, options: { type: JwtType }): DidJwtVerifier => {
  const { type } = options;
  if (!jwt.header.kid) throw new Error(`Received an invalid JWT. Missing kid header.`);
  if (!jwt.header.alg) throw new Error(`Received an invalid JWT. Missing alg header.`);

  if (!jwt.header.kid.includes('#')) {
    throw new Error(`Received an invalid JWT.. '${type}' contains an invalid kid header.`);
  }
  return { method: 'did', didUrl: jwt.header.kid, type: type, alg: jwt.header.alg as SigningAlgo };
};

export const getX5cVerifier = (jwt: { header: JwtHeader; payload: JwtPayload }, options: { type: JwtType }): X5cJwtVerifier => {
  const { type } = options;
  if (!jwt.header.x5c) throw new Error(`Received an invalid JWT. Missing x5c header.`);
  if (!jwt.header.alg) throw new Error(`Received an invalid JWT. Missing alg header.`);

  if (!Array.isArray(jwt.header.x5c) || jwt.header.x5c.length === 0 || !jwt.header.x5c.every((cert) => typeof cert === 'string')) {
    throw new Error(`Received an invalid JWT.. '${type}' contains an invalid x5c header.`);
  }

  if (typeof jwt.payload.iss !== 'string') {
    throw new Error(`Received an invalid JWT. '${type}' contains an invalid iss claim.`);
  }

  return { method: 'x5c', x5c: jwt.header.x5c, issuer: jwt.payload.iss, type: type, alg: jwt.header.alg as SigningAlgo };
};

export const getJwkVerifier = async (jwt: { header: JwtHeader; payload: JwtPayload }, options: { type: JwtType }): Promise<JwkJwtVerifier> => {
  const { type } = options;
  if (!jwt.header.jwk) throw new Error(`Received an invalid JWT.  Missing jwk header.`);
  if (!jwt.header.alg) throw new Error(`Received an invalid JWT. Missing alg header.`);

  if (typeof jwt.header.jwk !== 'object') {
    throw new Error(`Received an invalid JWT. '${type}' contains an invalid jwk header.`);
  }

  return { method: 'jwk', type, jwk: jwt.header.jwk, alg: jwt.header.alg as SigningAlgo };
};

export const getJwtVerifierWithContext = async (
  jwt: { header: JwtHeader; payload: JwtPayload },
  options: { type: JwtType },
): Promise<JwtVerifier> => {
  const { header, payload } = jwt;

  if (header.kid?.startsWith('did:')) return getDidJwtVerifier({ header, payload }, options);
  else if (jwt.header.x5c) return getX5cVerifier({ header, payload }, options);
  else if (jwt.header.jwk) return getJwkVerifier({ header, payload }, options);

  return { method: 'custom', type: options.type };
};

export type VerifyJwtCallbackBase<T extends JwtVerifier> = (
  jwtVerifier: T,
  jwt: { header: JwtHeader; payload: JwtPayload; raw: string },
) => Promise<boolean>;
