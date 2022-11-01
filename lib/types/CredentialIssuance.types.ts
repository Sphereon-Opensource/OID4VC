import { CredentialFormat, W3CVerifiableCredential } from '@sphereon/ssi-types';

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
  'pre-authorized_code'?: string; //CONDITIONAL the code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short-lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean | string; //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
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

export interface ProofOfPossessionCallbackArgs {
  privateKey: unknown;
  publicKey: unknown;
  header: JWTHeader;
  payload: JWTPayload;
  [x: string]: unknown;
}

export interface ProofOfPossessionOpts {
  clientId?: string;
  issuerURL?: string;
  proofOfPossessionCallback: JWTSignerCallback;
  proofOfPossessionVerifierCallback?: JWTVerifyCallback;
  proofOfPossessionCallbackArgs: ProofOfPossessionCallbackArgs;
}

export enum Alg {
  ES256 = 'ES256',
  EdDSA = 'EdDSA',
}

export enum Typ {
  JWT = 'JWT',
}

export interface JWTHeader {
  alg: Alg; // REQUIRED by the JWT signer
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
  jti: string; // A new nonce chosen by the wallet. Used to prevent replay
  exp?: number; // Not longer than 5 minutes
}

export type JWTSignerCallback = (args: { header?: JWTHeader; payload?: JWTPayload; [x: string]: unknown }) => Promise<string>;
export type JWTVerifyCallback = (args: { [x: string]: unknown }) => Promise<void>;

export type Request = CredentialRequest;
