import type { DIDResolutionResult, VerificationMethod } from 'did-resolver';

export interface EcdsaSignature {
  r: string;
  s: string;
  recoveryParam?: number | null;
}

// Signer interface conforming to the DID-JWT module
export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>;

export interface JWTPayload {
  iss?: string;
  sub?: string;
  aud?: string | string[];
  iat?: number;
  nbf?: number;
  type?: string;
  exp?: number;
  rexp?: number;
  jti?: string;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [x: string]: any;
}

export interface VerifiedJWT {
  payload: Partial<JWTPayload>; // The JWT payload
  didResolutionResult: DIDResolutionResult; // DID resolution result including DID document
  issuer: string; //The issuer (did) of the JWT
  signer: VerificationMethod; // The matching verification method from the DID that was used to sign
  jwt: string; // The JWT
}

/**
 * JSON Web Key ({@link https://www.rfc-editor.org/rfc/rfc7517 JWK}). "RSA", "EC", "OKP", and "oct"
 * key types are supported.
 */
export interface JWK {
  /** JWK "alg" (Algorithm) Parameter. */
  alg?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  /** JWK "ext" (Extractable) Parameter. */
  ext?: boolean;
  k?: string;
  /** JWK "key_ops" (Key Operations) Parameter. */
  key_ops?: string[];
  /** JWK "kid" (Key ID) Parameter. */
  kid?: string;
  /** JWK "kty" (Key Type) Parameter. */
  kty?: string;
  n?: string;
  oth?: Array<{
    d?: string;
    r?: string;
    t?: string;
  }>;
  p?: string;
  q?: string;
  qi?: string;
  /** JWK "use" (Public Key Use) Parameter. */
  use?: string;
  x?: string;
  y?: string;
  /** JWK "x5c" (X.509 Certificate Chain) Parameter. */
  x5c?: string[];
  /** JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter. */
  x5t?: string;
  /** "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter. */
  'x5t#S256'?: string;
  /** JWK "x5u" (X.509 URL) Parameter. */
  x5u?: string;

  [propName: string]: unknown;
}

// export declare type ECCurve = 'P-256' | 'secp256k1' | 'P-384' | 'P-521';
