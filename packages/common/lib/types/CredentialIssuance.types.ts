import { W3CVerifiableCredential } from '@sphereon/ssi-types';

import { AuthzFlowType } from './Authorization.types';
import { OID4VCICredentialFormat } from './Generic.types';
import { OpenId4VCIVersion } from './OpenID4VCIVersions.types';
import { CredentialOfferPayloadV1_0_08 } from './v1_0_08.types';
import { CredentialOfferPayloadV1_0_09, CredentialOfferV1_0_09 } from './v1_0_09.types';
import { CredentialOfferPayloadV1_0_11, CredentialOfferV1_0_11 } from './v1_0_11.types';

export interface CredentialResponse {
  credential?: W3CVerifiableCredential; // OPTIONAL. Contains issued Credential. MUST be present when acceptance_token is not returned. MAY be a JSON string or a JSON object, depending on the Credential format. See Appendix E for the Credential format specific encoding requirements
  format: OID4VCICredentialFormat /* | OID4VCICredentialFormat[]*/; // REQUIRED. JSON string denoting the format of the issued Credential
  transaction_id?: string; //OPTIONAL. A string identifying a Deferred Issuance transaction. This claim is contained in the response if the Credential Issuer was unable to immediately issue the credential. The value is subsequently used to obtain the respective Credential with the Deferred Credential Endpoint (see Section 9). It MUST be present when the credential parameter is not returned. It MUST be invalidated after the credential for which it was meant has been obtained by the Wallet.
  acceptance_token?: string; //deprecated // OPTIONAL. A JSON string containing a security token subsequently used to obtain a Credential. MUST be present when credential is not returned
  c_nonce?: string; // OPTIONAL. JSON string containing a nonce to be used to create a proof of possession of key material when requesting a Credential (see Section 7.2). When received, the Wallet MUST use this nonce value for its subsequent credential requests until the Credential Issuer provides a fresh nonce
  c_nonce_expires_in?: number; // OPTIONAL. JSON integer denoting the lifetime in seconds of the c_nonce
}

export interface CredentialOfferRequestWithBaseUrl extends UniformCredentialOfferRequest {
  scheme: string;
  clientId?: string;
  baseUrl: string;
  userPinRequired: boolean;
  issuerState?: string;
  preAuthorizedCode?: string;
}

export type CredentialOffer = CredentialOfferV1_0_09 | CredentialOfferV1_0_11;

export type CredentialOfferPayload = (CredentialOfferPayloadV1_0_08 | CredentialOfferPayloadV1_0_09 | CredentialOfferPayloadV1_0_11) & {
  [x: string]: any;
};

export interface AssertedUniformCredentialOffer extends UniformCredentialOffer {
  credential_offer: UniformCredentialOfferPayload;
}

export interface UniformCredentialOffer {
  credential_offer?: UniformCredentialOfferPayload;
  credential_offer_uri?: string;
}

export interface UniformCredentialOfferRequest extends AssertedUniformCredentialOffer {
  original_credential_offer: CredentialOfferPayload;
  version: OpenId4VCIVersion;
  supportedFlows: AuthzFlowType[];
}

export type UniformCredentialOfferPayload = CredentialOfferPayloadV1_0_11;

export interface ProofOfPossession {
  proof_type: 'jwt';
  jwt: string;

  [x: string]: unknown;
}

export type SearchValue = {
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [Symbol.replace](string: string, replacer: (substring: string, ...args: any[]) => string): string;
};

export enum JsonURIMode {
  JSON_STRINGIFY,
  X_FORM_WWW_URLENCODED,
}

export type EncodeJsonAsURIOpts = {
  uriTypeProperties?: string[];
  arrayTypeProperties?: string[];
  baseUrl?: string;
  param?: string;
  mode?: JsonURIMode;
  version?: OpenId4VCIVersion;
};

export type DecodeURIAsJsonOpts = {
  requiredProperties?: string[];
  arrayTypeProperties?: string[];
};

export interface BaseJWK {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
  e?: string;
  n?: string;
}

export interface JWK extends BaseJWK {
  alg?: string;
  d?: string;
  dp?: string;
  dq?: string;
  ext?: boolean;
  k?: string;
  key_ops?: string[];
  kid?: string;
  oth?: Array<{
    d?: string;
    r?: string;
    t?: string;
  }>;
  p?: string;
  q?: string;
  qi?: string;
  use?: string;
  x5c?: string[];
  x5t?: string;
  'x5t#S256'?: string;
  x5u?: string;

  [propName: string]: unknown;
}

export interface Jwt {
  header: JWTHeader;
  payload: JWTPayload;
}

export interface ProofOfPossessionCallbacks<DIDDoc> {
  signCallback: JWTSignerCallback;
  verifyCallback?: JWTVerifyCallback<DIDDoc>;
}

/**
 * Signature algorithms.
 *
 * TODO: Move towards string literal unions and string type, given we do not provide signature/key implementations in this library to begin with
 * @See: https://github.com/Sphereon-Opensource/OID4VCI/issues/88
 */
export enum Alg {
  EdDSA = 'EdDSA',
  ES256 = 'ES256',
  ES256K = 'ES256K',
  PS256 = 'PS256',
  PS384 = 'PS384',
  PS512 = 'PS512',
  RS256 = 'RS256',
  RS384 = 'RS384',
  RS512 = 'RS512',
}

export type Typ =
  | 'jwt'
  // https://www.rfc-editor.org/rfc/rfc8725.pdf#name-use-explicit-typing
  // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2.1-2.1.2.1.2.1.1
  | 'openid4vci-proof+jwt';

export interface JoseHeaderParameters {
  kid?: string; // CONDITIONAL. JWT header containing the key ID. If the Credential shall be bound to a DID, the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to. MUST NOT be present if jwk or x5c is present.
  x5t?: string;
  x5c?: string[]; // CONDITIONAL. JWT header containing a certificate or certificate chain corresponding to the key used to sign the JWT. This element may be used to convey a key attestation. In such a case, the actual key certificate will contain attributes related to the key properties. MUST NOT be present if kid or jwk is present.
  x5u?: string;
  jku?: string;
  jwk?: BaseJWK; // CONDITIONAL. JWT header containing the key material the new Credential shall be bound to. MUST NOT be present if kid or x5c is present.
  typ?: string; //JWT always
  cty?: string;
}

export interface JWSHeaderParameters extends JoseHeaderParameters {
  alg?: Alg | string; // REQUIRED by the JWT signer
  b64?: boolean;
  crit?: string[];

  [propName: string]: unknown;
}

export interface CompactJWSHeaderParameters extends JWSHeaderParameters {
  alg: string;
}

export interface JWTHeaderParameters extends CompactJWSHeaderParameters {
  b64?: true;
}

export type JWTHeader = JWTHeaderParameters;

export interface JWTPayload {
  iss?: string; // REQUIRED (string). The value of this claim MUST be the client_id of the client making the credential request.
  aud?: string | string[]; // REQUIRED (string). The value of this claim MUST be the issuer URL of credential issuer.
  iat?: number; // REQUIRED (number). The value of this claim MUST be the time at which the proof was issued using the syntax defined in [RFC7519].
  nonce?: string; // REQUIRED (string). The value type of this claim MUST be a string, where the value is a c_nonce provided by the credential issuer. //TODO: Marked as required not present in NGI flow
  jti?: string; // A new nonce chosen by the wallet. Used to prevent replay
  exp?: number; // Not longer than 5 minutes
  [s: string]: unknown;
}

export type JWTSignerCallback = (jwt: Jwt, kid?: string) => Promise<string>;
export type JWTVerifyCallback<DIDDoc> = (args: { jwt: string; kid?: string }) => Promise<JwtVerifyResult<DIDDoc>>;

export interface JwtVerifyResult<DIDDoc> {
  jwt: Jwt;
  kid?: string;
  alg: string;
  did?: string;
  didDocument?: DIDDoc;
  x5c?: string;
  jwk?: BaseJWK;
}
