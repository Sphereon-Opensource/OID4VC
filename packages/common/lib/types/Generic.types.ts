import { ICredentialContextType, IVerifiableCredential, W3CVerifiableCredential } from '@sphereon/ssi-types';

import { ProofOfPossession } from './CredentialIssuance.types';
import { AuthorizationServerMetadata } from './ServerMetadata';
import { CredentialOfferSession } from './StateManager.types';
import { CredentialRequestV1_0_12 } from './v1_0_12.types';

/**
 * Important Note: please be aware that these Common interfaces are based on versions v1_0.11 and v1_0.09
 */
export interface ImageInfo {
  url?: string;
  alt_text?: string;

  [key: string]: unknown;
}

export type OID4VCICredentialFormat = 'jwt_vc_json' | 'jwt_vc_json-ld' | 'ldp_vc' | 'vc+sd-jwt' | 'jwt_vc'; // jwt_vc is added for backwards compat /*| 'mso_mdoc'*/; // we do not support mdocs at this point

export type KeyProofType = 'jwt' | 'cwt'

export type JWAlgorithm =
  'HS256' | // HMAC using SHA-256
  'HS384' | // HMAC using SHA-384
  'HS512' | // HMAC using SHA-512
  'RS256' | // RSASSA-PKCS1-v1_5 using SHA-256
  'RS384' | // RSASSA-PKCS1-v1_5 using SHA-384
  'RS512' | // RSASSA-PKCS1-v1_5 using SHA-512
  'ES256' | // ECDSA using P-256 and SHA-256
  'ES384' | // ECDSA using P-384 and SHA-384
  'ES512' | // ECDSA using P-521 and SHA-512
  'PS256' | // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
  'PS384' | // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
  'PS512' | // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
  'none'  // No digital signature or MAC performed

export interface NameAndLocale {
  name?: string; // REQUIRED. String value of a display name for the Credential.
  locale?: string; // OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. Multiple display objects MAY be included for separate languages. There MUST be only one object with the same language identifier.
  [key: string]: unknown;
}

export interface LogoAndColor {
  logo?: ImageInfo; // OPTIONAL. A JSON object with information about the logo of the Credential with a following non-exhaustive list of parameters that MAY be included:
  description?: string; // OPTIONAL. String value of a description of the Credential.
  background_color?: string; //OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
  text_color?: string; // OPTIONAL. String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
}


export type CredentialsSupportedDisplay = NameAndLocale &
  LogoAndColor & {
    name: string // REQUIRED. String value of a display name for the Credential.
    locale?: string // OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47
    description?: string // OPTIONAL. String value of a description of the Credential.
  };

export type MetadataDisplay = NameAndLocale &
  LogoAndColor & {
    name?: string; //OPTIONAL. String value of a display name for the Credential Issuer.
  };

export interface CredentialSupplierConfig {
  [key: string]: any; // This allows additional properties for credential suppliers
}

export interface CredentialIssuerMetadataOpts {
  credential_issuer: string; // REQUIRED. The Credential Issuer's identifier.
  authorization_servers?: string[]; // OPTIONAL. Identifier of the OAuth 2.0 Authorization Server (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  credential_endpoint?: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  batch_credential_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components. If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
  deferred_credential_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Deferred Credential Endpoint.
  credential_response_encryption_alg_values_supported?: JWAlgorithm[] // OPTIONAL. Array containing a list of the JWE [RFC7516] encryption algorithms (alg values)
  credential_response_encryption_enc_values_supported?: JWAlgorithm[] // OPTIONAL. Array containing a list of the JWE [RFC7516] encryption algorithms (enc values)
  require_credential_response_encryption?: boolean // OPTIONAL. Boolean value specifying whether the Credential Issuer requires additional encryption on top of TLS for the Credential Response and expects encryption parameters to be present in the Credential Request and/or Batch Credential Request, with true indicating support. When the value is true, credential_response_encryption_alg_values_supported parameter MUST also be provided. If omitted, the default value is false
  credential_identifiers_supported?: boolean // OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning credential_identifiers parameter in the authorization_details Token Response parameter, with true indicating support. If omitted, the default value is false.
  display?: MetadataDisplay[]; //  An array of objects, where each object contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
  credentials_supported: CredentialSupported[]; // REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
  token_endpoint?: string; // CUSTOM out of spec
  credential_supplier_config?: CredentialSupplierConfig; // CUSTOM out of spec
}

// For now we extend the opts above. Only difference is that the credential endpoint is optional in the Opts, as it can come from other sources. The value is however required in the eventual Issuer Metadata
export interface CredentialIssuerMetadata extends CredentialIssuerMetadataOpts, Partial<AuthorizationServerMetadata> {
  credential_endpoint: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
}

export interface CredentialSupportedBrief {
  cryptographic_binding_methods_supported?: string[]; // OPTIONAL. Array of case sensitive strings that identify how the Credential is bound to the identifier of the End-User who possesses the Credential
  cryptographic_suites_supported?: string[]; // OPTIONAL. Array of case sensitive strings that identify the cryptographic suites that are supported for the cryptographic_binding_methods_supported
}

export type CommonCredentialSupported = CredentialSupportedBrief & {
    format: OID4VCICredentialFormat | string; // REQUIRED. A JSON string identifying the format of this credential, i.e., jwt_vc_json or ldp_vc. Depending on the format value, the object contains further elements defining the type and (optionally) particular claims the credential MAY contain and information about how to display the credential.
    // id is @Deprecated V12, but still in use I see
    id?: string; // OPTIONAL. A JSON string identifying the respective object. The value MUST be unique across all credentials_supported entries in the Credential Issuer Metadata
    scope?: string; // OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this particular credential. The value can be the same across multiple credentials_supported objects.  Scope values in this Credential Issuer metadata MAY duplicate those in the scopes_supported parameter of the Authorization Server.
    proof_types_supported?: KeyProofType[];
    display?: CredentialsSupportedDisplay[];
};


export interface JwtVcCredentialDefinition  {
  type: string[]; // REQUIRED. JSON array designating the types a certain credential type supports
  credentialSubject?: IssuerCredentialSubject; // OPTIONAL. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the verifiable credential to be issued.
}

export interface JwtVcJsonLdAndLdpVcCredentialDefinition extends JwtVcCredentialDefinition {
  type: string[]; // REQUIRED. JSON array designating the types a certain credential type supports
  '@context': ICredentialContextType[]; // REQUIRED. JSON array as defined in [VC_DATA], Section 4.1.
  credentialSubject?: IssuerCredentialSubject; // OPTIONAL. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the verifiable credential to be issued.
}

export interface CredentialSupportedJwtVcJsonLdAndLdpVc extends CommonCredentialSupported {
  credential_definition: JwtVcJsonLdAndLdpVcCredentialDefinition; // REQUIRED. JSON object containing the detailed description of the credential type
  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
  format: 'ldp_vc' | 'jwt_vc_json-ld';
}

export interface JwtVcCredentialDefinition {
  type: string[]; // REQUIRED. JSON array designating the types a certain credential type supports
  credentialSubject?: IssuerCredentialSubject; // OPTIONAL. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the verifiable credential to be issued.
}


export interface CredentialSupportedJwtVcJson extends CommonCredentialSupported {
  credential_definition: JwtVcCredentialDefinition; // REQUIRED. JSON object containing the detailed description of the credential type
  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
  format: 'jwt_vc_json' | 'jwt_vc'; // jwt_vc added for backwards compat
}

export interface CredentialSupportedSdJwtVc extends CommonCredentialSupported {
  format: 'vc+sd-jwt';

  vct: string;
  claims?: IssuerCredentialSubject;

  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export type CredentialSupported = CommonCredentialSupported &
  (CredentialSupportedJwtVcJson | CredentialSupportedJwtVcJsonLdAndLdpVc | CredentialSupportedSdJwtVc);

export interface CommonCredentialOfferFormat {
  format: OID4VCICredentialFormat | string;
}

export interface CredentialOfferFormatJwtVcJsonLdAndLdpVc extends CommonCredentialOfferFormat {
  format: 'ldp_vc' | 'jwt_vc_json-ld';
  // REQUIRED. JSON object containing (and isolating) the detailed description of the credential type. This object MUST be processed using full JSON-LD processing.
  credential_definition: JsonLdIssuerCredentialDefinition;
}

export interface CredentialOfferFormatJwtVcJson extends CommonCredentialOfferFormat {
  format: 'jwt_vc_json' | 'jwt_vc'; // jwt_vc is added for backwards compat
  types: string[]; // REQUIRED. JSON array as defined in Appendix E.1.1.2. This claim contains the type values the Wallet shall request in the subsequent Credential Request.
}

// NOTE: the sd-jwt format is added to oid4vci in a later draft version than currently
// supported, so there's no defined offer format. However, based on the request structure
// we support sd-jwt for older drafts of oid4vci as well
export interface CredentialOfferFormatSdJwtVc extends CommonCredentialOfferFormat {
  format: 'vc+sd-jwt';

  vct: string;
  claims?: IssuerCredentialSubject;
}

export type CredentialOfferFormat = CommonCredentialOfferFormat &
  (CredentialOfferFormatJwtVcJsonLdAndLdpVc | CredentialOfferFormatJwtVcJson | CredentialOfferFormatSdJwtVc);

/**
 * Optional storage that can help the credential Data Supplier. For instance to store credential input data during offer creation, if no additional data can be supplied later on
 */
export type CredentialDataSupplierInput = any;

export type CreateCredentialOfferURIResult = {
  uri: string;
  qrCodeDataUri?: string;
  session: CredentialOfferSession;
  userPin?: string;
  userPinLength?: number;
  userPinRequired: boolean;
};

export interface JsonLdIssuerCredentialDefinition {
  '@context': ICredentialContextType[];
  type: string[];
  credentialSubject?: IssuerCredentialSubject;
}

export interface ErrorResponse extends Response {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export type UniformCredentialRequest = CredentialRequestV1_0_12;

export interface CommonCredentialRequest {
  format: OID4VCICredentialFormat /* | OID4VCICredentialFormat[];*/; // for now it seems only one is supported in the spec
  proof?: ProofOfPossession;
}

export interface CredentialRequestJwtVcJson extends CommonCredentialRequest {
  format: 'jwt_vc_json' | 'jwt_vc'; // jwt_vc for backwards compat
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
}

export interface CredentialRequestJwtVcJsonLdAndLdpVc extends CommonCredentialRequest {
  format: 'ldp_vc' | 'jwt_vc_json-ld';
  credential_definition: JsonLdIssuerCredentialDefinition;
}

export interface CredentialRequestSdJwtVc extends CommonCredentialRequest {
  format: 'vc+sd-jwt';
  vct: string;
  claims?: IssuerCredentialSubject;
}

export interface CommonCredentialResponse {
  format: string;
  credential?: W3CVerifiableCredential;
  acceptance_token?: string;
  c_nonce?: string;
  c_nonce_expires_in?: string;
}

export interface CredentialResponseLdpVc extends CommonCredentialResponse {
  format: 'ldp_vc';
  credential: IVerifiableCredential;
}

export interface CredentialResponseJwtVc {
  format: 'jwt_vc_json' | 'jwt_vc_json-ld';
  credential: string;
}

export interface CredentialResponseSdJwtVc {
  format: 'vc+sd-jwt';
  credential: string;
}

// export type CredentialSubjectDisplay = NameAndLocale[];

export type IssuerCredentialSubjectDisplay = CredentialSubjectDisplay & { [key: string]: CredentialSubjectDisplay };

export interface CredentialSubjectDisplay {
  mandatory?: boolean; // OPTIONAL. Boolean which when set to true indicates the claim MUST be present in the issued Credential. If the mandatory property is omitted its default should be assumed to be false.
  value_type?: string; // OPTIONAL. String value determining type of value of the claim. A non-exhaustive list of valid values defined by this specification are string, number, and image media types such as image/jpeg as defined in IANA media type registry for images
  display?: NameAndLocale[]; // OPTIONAL. An array of objects, where each object contains display properties of a certain claim in the Credential for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
}

export interface IssuerCredentialSubject {
  [key: string]: IssuerCredentialSubjectDisplay;
}

export interface Grant {
  authorization_code?: GrantAuthorizationCode;
  'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: GrantUrnIetf;
}

export interface GrantAuthorizationCode {
  /**
   * OPTIONAL. String value created by the Credential Issuer and opaque to the Wallet that is used to bind the subsequent
   * Authorization Request with the Credential Issuer to a context set up during previous steps.
   */
  issuer_state?: string;
}

export interface GrantUrnIetf {
  /**
   * REQUIRED. The code representing the Credential Issuer's authorization for the Wallet to obtain Credentials of a certain type.
   */
  'pre-authorized_code': string
  /**
   * OPTIONAL. Boolean value specifying whether the Credential Issuer expects presentation of a user PIN along with the Token Request
   * in a Pre-Authorized Code Flow. Default is false.
   */
  user_pin_required?: boolean

  /**
   * OPTIONAL. The minimum amount of time in seconds that the Wallet SHOULD wait between polling requests to the token endpoint (in case the Authorization Server responds with error code authorization_pending - see Section 6.3). If no value is provided, Wallets MUST use 5 as the default.
   */
  interval?: number

  /**
   * OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant type when authorization_servers parameter in the Credential Issuer metadata has multiple entries. MUST NOT be used otherwise. The value of this parameter MUST match with one of the values in the authorization_servers array obtained from the Credential Issuer metadata.
   */
  authorization_server?: string
}

export const PRE_AUTH_CODE_LITERAL = 'pre-authorized_code';
