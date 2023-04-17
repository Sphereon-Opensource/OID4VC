import { CredentialFormat, ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types';

import { OpenId4VCIVersion } from './OpenID4VCIVersions.types';
import { CredentialOfferPayloadV1_0_09 } from './v1_0_09.types';
import { CredentialOfferPayloadV1_0_11 } from './v1_0_11.types';

export interface CredentialRequest {
  //TODO: handling list is out of scope for now
  type: string | string[];
  format: CredentialFormat | CredentialFormat[];
  proof: ProofOfPossession;
}

export interface CredentialResponse {
  credential: W3CVerifiableCredential;
  format: CredentialFormat | CredentialFormat[];
}

export interface CredentialOfferRequestWithBaseUrl {
  baseUrl: string;
  request: CredentialOfferPayloadV1_0_09 | CredentialOfferPayloadV1_0_11;
  version: OpenId4VCIVersion;
}

export type CredentialOfferPayload = CredentialOfferPayloadV1_0_09 | CredentialOfferPayloadV1_0_11;

export enum ProofType {
  JWT = 'jwt',
}

export interface ProofOfPossession {
  proof_type: ProofType;
  jwt: string;

  [x: string]: unknown;
}

export type SearchValue = {
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [Symbol.replace](string: string, replacer: (substring: string, ...args: any[]) => string): string;
};

export type EncodeJsonAsURIOpts = {
  uriTypeProperties?: string[];
  arrayTypeProperties?: string[];
  baseUrl?: string;
};

export type DecodeURIAsJsonOpts = {
  requiredProperties?: string[];
  arrayTypeProperties?: string[];
};

export interface JWK {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
  e?: string;
  n?: string;
}

export interface Jwt {
  header: JWTHeader;
  payload: JWTPayload;
}

export interface ProofOfPossessionCallbacks {
  signCallback: JWTSignerCallback;
  verifyCallback?: JWTVerifyCallback;
}

export enum Alg {
  EdDSA = 'EdDSA',
  ES256 = 'ES256',
  ES256K = 'ES256K',
}

export enum Typ {
  JWT = 'JWT',
  // https://www.rfc-editor.org/rfc/rfc8725.pdf#name-use-explicit-typing
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2.1-2.1.2.1.2.1.1
  'OPENID4VCI-PROOF+JWT' = 'openid4vci-proof+jwt',
}

export interface JWTHeader {
  alg: Alg | string; // REQUIRED by the JWT signer
  typ?: string; //JWT always
  kid?: string; // CONDITIONAL. JWT header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to. MUST NOT be present if jwk or x5c is present.
  jwk?: JWK; // CONDITIONAL. JWT header containing the key material the new Credential shall be bound to. MUST NOT be present if kid or x5c is present.
  x5c?: string[]; // CONDITIONAL. JWT header containing a certificate or certificate chain corresponding to the key used to sign the JWT. This element may be used to convey a key attestation. In such a case, the actual key certificate will contain attributes related to the key properties. MUST NOT be present if kid or jwk is present.
}

export interface JWTPayload {
  iss?: string; // REQUIRED (string). The value of this claim MUST be the client_id of the client making the credential request.
  aud?: string; // REQUIRED (string). The value of this claim MUST be the issuer URL of credential issuer.
  iat?: number; // REQUIRED (number). The value of this claim MUST be the time at which the proof was issued using the syntax defined in [RFC7519].
  nonce?: string; // REQUIRED (string). The value type of this claim MUST be a string, where the value is a c_nonce provided by the credential issuer. //TODO: Marked as required not present in NGI flow
  jti?: string; // A new nonce chosen by the wallet. Used to prevent replay
  exp?: number; // Not longer than 5 minutes
}

export type JWTSignerCallback = (jwt: Jwt, kid?: string) => Promise<string>;
export type JWTVerifyCallback = (args: { jwt: string; kid?: string }) => Promise<Jwt>;

export type Request = CredentialRequest;

export type CredentialIssuerCallback = (opts: {
  credentialRequest?: CredentialRequest;
  credential?: ICredential;
}) => Promise<W3CVerifiableCredential>;
