import { KeyObject } from 'crypto';

import { CredentialFormat, W3CVerifiableCredential } from '@sphereon/ssi-types';

export enum AuthzFlowType {
  AUTHORIZATION_CODE_FLOW = 'Authorization Code Flow',
  PRE_AUTHORIZED_CODE_FLOW = 'Pre-Authorized Code Flow',
}

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace AuthzFlowType {
  export function valueOf(request: IssuanceInitiationRequestPayload): AuthzFlowType {
    if (request.pre_authorized_code) {
      return AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW;
    }
    return AuthzFlowType.AUTHORIZATION_CODE_FLOW;
  }
}

export interface CredentialRequest {
  //TODO: handling list is out of scope for now
  type: string | string[];
  //TODO: handling list is out of scope for now
  format: CredentialFormat | CredentialFormat[];
  proof: ProofOfPossession;
}

export interface CredentialResponse {
  credential: W3CVerifiableCredential;
  format: CredentialFormat;
}

export interface IssuanceInitiationWithBaseUrl {
  baseUrl: string;
  issuanceInitiationRequest: IssuanceInitiationRequestPayload;
}

export interface IssuanceInitiationRequestPayload {
  issuer: string; //(url) REQUIRED The issuer URL of the Credential issuer, the Wallet is requested to obtain one or more Credentials from.
  credential_type: string[] | string; //(url) REQUIRED A JSON string denoting the type of the Credential the Wallet shall request
  pre_authorized_code?: string; //CONDITIONAL the code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short-lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean; //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
  op_state?: string; //(JWT) OPTIONAL String value created by the Credential Issuer and opaque to the Wallet that is used to bind the subsequent authentication request with the Credential Issuer to a context set up during previous steps
}

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

export type EncodeJsonAsURIOpts = { uriTypeProperties?: string[]; arrayTypeProperties?: string[]; baseUrl?: string };

export type DecodeURIAsJsonOpts = { requiredProperties?: string[]; arrayTypeProperties?: string[] };

export interface JWK {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
  e?: string;
  n?: string;
}

export type Alg = 'ES256' | 'EdDSA';

export interface JWTHeader {
  alg: Alg; // REQUIRED by the JWT signer
  typ?: string; //JWT always
  kid?: string; // CONDITIONAL. JWT header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to. MUST NOT be present if jwk or x5c is present.
  jwk?: JWK; // CONDITIONAL. JWT header containing the key material the new Credential shall be bound to. MUST NOT be present if kid or x5c is present.
  x5c?: string[]; // CONDITIONAL. JWT header containing a certificate or certificate chain corresponding to the key used to sign the JWT. This element may be used to convey a key attestation. In such a case, the actual key certificate will contain attributes related to the key properties. MUST NOT be present if kid or jwk is present.
}

export interface JWTPayload {
  iss: string; // REQUIRED (string). The value of this claim MUST be the client_id of the client making the credential request.
  aud?: string; // REQUIRED (string). The value of this claim MUST be the issuer URL of credential issuer.
  iat?: number; // REQUIRED (number). The value of this claim MUST be the time at which the proof was issued using the syntax defined in [RFC7519].
  nonce: string; // REQUIRED (string). The value type of this claim MUST be a string, where the value is a c_nonce provided by the credential issuer.
  jti: string; // A new nonce chosen by the wallet. Used to prevent replay
  exp?: number; // Not longer than 5 minutes
}

export interface JWTSignerArgs {
  header: JWTHeader;
  payload: JWTPayload;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export interface JWTVerifyArgs {
  jws: string;
  key: KeyObject;
  algorithms?: Alg[];
}

export interface ProofOfPossessionOpts {
  credentialRequestUrl: string;
  jwtSignerArgs: JWTSignerArgs;
  jwtSignerCallback: JWTSignerCallback;
  jwtVerifyCallback?: JWTVerifyCallback;
}

export type JWTSignerCallback = (args: JWTSignerArgs) => Promise<string>;

export type JWTVerifyCallback = (args: JWTVerifyArgs) => Promise<void>;

export type Request = CredentialRequest;
