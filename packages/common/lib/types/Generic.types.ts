import { ICredentialContextType, IVerifiableCredential, W3CVerifiableCredential } from '@sphereon/ssi-types';

import { ProofOfPossession } from './CredentialIssuance.types';
import { Oauth2ASWithOID4VCIMetadata } from './OpenID4VCIServerMetadata';
import { CredentialRequestV1_0_11 } from './v1_0_11.types';

/**
 * Important Note: please be aware that these Common interfaces are based on versions v1_0.11 and v1_0.09
 */
export interface CredentialLogo {
  url?: string;
  alt_text?: string;

  [key: string]: unknown;
}

export type OID4VCICredentialFormat = 'jwt_vc_json' | 'jwt_vc_json_ld' | 'ldp_vc' /*| 'mso_mdoc'*/; // we do not support mdocs at this point

export interface NameAndLocale {
  name?: string; // REQUIRED. String value of a display name for the Credential.
  locale?: string; // OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. Multiple display objects MAY be included for separate languages. There MUST be only one object with the same language identifier.
  [key: string]: unknown;
}

export interface LogoAndColor {
  logo?: CredentialLogo; // OPTIONAL. A JSON object with information about the logo of the Credential with a following non-exhaustive list of parameters that MAY be included:
  description?: string; // OPTIONAL. String value of a description of the Credential.
  background_color?: string; //OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
  text_color?: string; // OPTIONAL. String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
}

export type CredentialsSupportedDisplay = NameAndLocale &
  LogoAndColor & {
    name: string; // REQUIRED. String value of a display name for the Credential.
  };

export type MetadataDisplay = NameAndLocale &
  LogoAndColor & {
    name?: string; //OPTIONAL. String value of a display name for the Credential Issuer.
  };

export interface CredentialIssuerMetadataOpts {
  credential_endpoint?: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  batch_credential_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components. If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
  credentials_supported: CredentialSupported[]; // REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
  credential_issuer: string; // REQUIRED. The Credential Issuer's identifier.
  authorization_server?: string; // OPTIONAL. Identifier of the OAuth 2.0 Authorization Server (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  token_endpoint?: string;
  display?: MetadataDisplay[]; //  An array of objects, where each object contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
}

// For now we extend the opts above. Only difference is that the credential endpoint is optional in the Opts, as it can come from other sources. The value is however required in the eventual Issuer Metadata
export interface CredentialIssuerMetadata extends CredentialIssuerMetadataOpts {
  credential_endpoint: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  /*batch_credential_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components. If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
  credentials_supported: CredentialSupported[]; // REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
  credential_issuer: string; // REQUIRED. The Credential Issuer's identifier.
  authorization_server?: string; // OPTIONAL. Identifier of the OAuth 2.0 Authorization Server (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  token_endpoint?: string;
  display?: MetadataDisplay[]; //  An array of objects, where each object contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:*/
}

export interface CredentialSupportedBrief {
  name?: string; // fixme: Probably should not be here, is part of the display object
  types: string[]; // REQUIRED. JSON array designating the types a certain credential type supports
  cryptographic_binding_methods_supported?: string[]; // OPTIONAL. Array of case sensitive strings that identify how the Credential is bound to the identifier of the End-User who possesses the Credential
  cryptographic_suites_supported?: string[]; // OPTIONAL. Array of case sensitive strings that identify the cryptographic suites that are supported for the cryptographic_binding_methods_supported
}

export type CommonCredentialSupported = CredentialSupportedBrief & {
  format: OID4VCICredentialFormat | string; //REQUIRED. A JSON string identifying the format of this credential, e.g. jwt_vc_json or ldp_vc.
  id?: string; // OPTIONAL. A JSON string identifying the respective object. The value MUST be unique across all credentials_supported entries in the Credential Issuer Metadata
  display?: CredentialsSupportedDisplay[]; // OPTIONAL. An array of objects, where each object contains the display properties of the supported credential for a certain language
  /**
   * following properties are non-mso_mdoc specific and we might wanna rethink them when we're going to support mso_mdoc
   */
  credentialSubject?: IssuerCredentialSubject; // OPTIONAL. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the verifiable credential to be issued.
  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
};

export interface CredentialSupportedJwtVcJsonLdAndLdpVc extends CommonCredentialSupported {
  '@context': ICredentialContextType[]; // REQUIRED. JSON array as defined in [VC_DATA], Section 4.1.
}

export interface CredentialSupportedJwtVcJson extends CommonCredentialSupported {
  format: 'jwt_vc_json';
}

export type CredentialSupported = CommonCredentialSupported & (CredentialSupportedJwtVcJson | CredentialSupportedJwtVcJsonLdAndLdpVc);

export interface CredentialOfferFormat {
  format: OID4VCICredentialFormat | string;
  types: string[];
}

export interface IssuerCredentialDefinition {
  '@context': ICredentialContextType[];
  types: string[];
  credentialSubject: IssuerCredentialSubject;
}

export interface CredentialOfferCredentialDefinition {
  '@context': ICredentialContextType[];
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
  order?: string[]; // An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export enum GrantType {
  AUTHORIZATION_CODE = 'authorization_code',
  PRE_AUTHORIZED_CODE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  PASSWORD = 'password',
}

export interface CommonAccessTokenRequest {
  client_id?: string;
  code?: string;
  code_verifier?: string;
  grant_type: GrantType;
  'pre-authorized_code'?: string;
  redirect_uri?: string;
  scope?: string;
  user_pin?: string;
}

export enum TokenErrorResponse {
  invalid_request = 'invalid_request',
  invalid_grant = 'invalid_grant',
  invalid_client = 'invalid_client', // this code has been added only in v1_0-11, but I've added this to the common interface. @nklomp is this ok?
  invalid_scope = 'invalid_scope',
}

export interface CommonAccessTokenResponse {
  access_token: string;
  scope?: string;
  token_type?: string;
  expires_in?: number; // in seconds
  c_nonce?: string;
  c_nonce_expires_in?: number; // in seconds
  authorization_pending?: boolean;
  interval?: number; // in seconds
}

export interface ErrorResponse extends Response {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}

export type UniformCredentialRequest = CredentialRequestV1_0_11;

export interface CommonCredentialRequest {
  format: OID4VCICredentialFormat /* | OID4VCICredentialFormat[];*/; // for now it seems only one is supported in the spec
  proof?: ProofOfPossession;
}

export interface CredentialRequestJwtVcJson extends CommonCredentialRequest {
  format: 'jwt_vc_json';
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
}

export interface CredentialRequestJwtVcJsonLdAndLdpVc extends CommonCredentialRequest {
  format: 'jwt_vc_json_ld' | 'ldp_vc';
  credential_definition: IssuerCredentialDefinition;
}

export interface CommonCredentialResponse {
  format: string;
  credential?: W3CVerifiableCredential;
  acceptance_token?: string;
  c_nonce?: string;
  c_nonce_expires_in?: string;
}

export interface CredentialResponseJwtVcJsonLdAndLdpVc extends CommonCredentialResponse {
  format: 'jwt_vc_json_ld' | 'ldp_vc';
  credential: IVerifiableCredential;
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

export interface CredentialResponseJwtVcJson {
  credential: string;
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
  'pre-authorized_code': string;
  /**
   * OPTIONAL. Boolean value specifying whether the Credential Issuer expects presentation of a user PIN along with the Token Request
   * in a Pre-Authorized Code Flow. Default is false.
   */
  user_pin_required: boolean;
}

export const PRE_AUTH_CODE_LITERAL = 'pre-authorized_code';

export enum WellKnownEndpoints {
  OPENID_CONFIGURATION = '/.well-known/openid-configuration',
  OAUTH_AS = '/.well-known/oauth-authorization-server',
  OPENID4VCI_ISSUER = '/.well-known/openid-credential-issuer',
}

export interface EndpointMetadata {
  issuer: string;
  token_endpoint: string;
  credential_endpoint: string;
  authorization_endpoint?: string;
  issuerMetadata?: CredentialIssuerMetadata | Oauth2ASWithOID4VCIMetadata;
}
