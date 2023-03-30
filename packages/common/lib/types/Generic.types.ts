import { ICredentialContextType, IVerifiableCredential, W3CVerifiableCredential } from '@sphereon/ssi-types';

import { CodeChallengeMethod, ResponseType } from './Authorization.types';
import { ProofOfPossession } from './CredentialIssuance.types';
import { OpenID4VCIServerMetadata } from './OpenID4VCIServerMetadata';

/**
 * Important Note: please be aware that these Common interfaces are based on versions v1_0.11 and v1_0.09
 */
export interface CredentialLogo {
  url?: string;
  alt_text?: string;
}

export enum CredentialFormatEnum {
  jwt_vc_json = 'jwt_vc_json',
  jwt_vc_json_ld = 'jwt_vc_json_ld',
  ldp_vc = 'ldp_vc',
  mso_mdoc = 'mso_mdoc',
}

export interface NameAndLocale {
  name?: string;
  locale?: string;
}

export interface Display extends NameAndLocale {
  logo?: CredentialLogo;
  background_color?: string;
  text_color?: string;
}

export interface IssuerMetadata {
  credential_endpoint: string;
  batch_credential_endpoint?: string;
  credentials_supported: CredentialIssuerMetadataSupportedCredentials[];
  credential_issuer: Display;
}

export interface CredentialIssuerMetadataSupportedCredentials {
  format: CredentialFormatEnum;
  id?: string;
  cryptographic_binding_methods_supported?: string[];
  cryptographic_suites_supported?: string[];
}

export interface SupportedCredentialIssuerMetadataJwtVcJsonLdAndLdpVc extends CredentialIssuerMetadataSupportedCredentials {
  format: CredentialFormatEnum.ldp_vc;
  '@context': ICredentialContextType[];
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
  display?: Display[];
}

export interface SupportedCredentialIssuerMetadataJwtVcJson extends CredentialIssuerMetadataSupportedCredentials {
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
  display?: Display[];
  order?: string[]; //An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export interface MsoClaims {
  // key is a certain namespace as defined in [ISO.18013-5] (or any profile of it) examples: "org.iso.18013.5.1", "org.iso.18013.5.1.aamva"
  [key: string]: {
    [key: string]: {
      mandatory?: boolean;
      value_type?: string;
      display?: Display[];
    };
  };
}
export interface SupportedCredentialIssuerMetadataMsoMdoc extends CredentialIssuerMetadataSupportedCredentials {
  format: CredentialFormatEnum.mso_mdoc;
  doctype: string;
  claims?: MsoClaims;
  order?: string[];
}

export interface CredentialOfferCredential {
  format: CredentialFormatEnum;
}

export interface CredentialOfferCredentialJwtVcJson extends CredentialOfferCredential {
  format: CredentialFormatEnum.jwt_vc_json;
  types: string[];
}
export interface CredentialOfferCredentialMsoMdoc extends CredentialOfferCredential {
  format: CredentialFormatEnum.mso_mdoc;
  doctype: string;
}

export interface IssuerCredentialDefinition {
  '@context': ICredentialContextType[];
  types: string[];
  credentialSubject: IssuerCredentialSubject;
}

//todo: change this back to AuthorizationRequest once merged with latest changes from develop
export interface AbstractAuthorizationRequest {
  response_type: ResponseType.AUTH_CODE;
  client_id: string;
  code_challenge: string;
  code_challenge_method: CodeChallengeMethod;
  redirect_uri: string;
  scope?: string;
  authorization_details?: AbstractAuthorizationDetails[];
  wallet_issuer?: string;
  user_hint?: string;
}

export interface AuthorizationRequestJwtVcJson extends AbstractAuthorizationRequest {
  authorization_details?: AuthorizationDetailsJwtVcJson[];
}

export interface AuthorizationRequestJwtVcJsonLdAndLdpVc extends AbstractAuthorizationRequest {
  authorization_details?: AuthorizationDetailsJwtVcJsonLdAndLdpVc[];
}

export interface AuthorizationRequestMsoDoc extends AbstractAuthorizationRequest {
  authorization_details?: AuthorizationDetailsMsoDoc[];
}

export interface AbstractAuthorizationDetails {
  type: 'openid_credential';
  format: CredentialFormatEnum;
}

export interface AuthorizationDetailsJwtVcJson extends AbstractAuthorizationDetails {
  format: CredentialFormatEnum.jwt_vc_json;
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
}

export interface AuthorizationDetailsJwtVcJsonLdAndLdpVc extends AbstractAuthorizationDetails {
  format: CredentialFormatEnum.ldp_vc | CredentialFormatEnum.jwt_vc_json_ld;
  types: string[];
  credential_definition: IssuerCredentialDefinition;
}

export interface AuthorizationDetailsMsoDoc extends AbstractAuthorizationDetails {
  format: CredentialFormatEnum.mso_mdoc;
  doctype: string;
  claims?: MsoClaims;
}

export interface CredentialOfferCredentialDefinition {
  '@context': ICredentialContextType[];
  types: string[];
  CredentialSubject?: IssuerCredentialSubject;
}

export enum GrantType {
  AUTHORIZATION_CODE = 'authorization_code',
  PRE_AUTHORIZED_CODE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  PASSWORD = 'password',
}

//todo: change this back to AccessTokenRequest once merged with latest changes from develop
export interface GenericAccessTokenRequest {
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
}

//todo: change this back to AccessTokenResponse once merged with latest changes from develop
export interface GenericAccessTokenResponse {
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

//todo: change this back to CredentialRequest once merged with latest changes from develop
export interface AbstractCredentialRequest {
  format: string;
  proof?: ProofOfPossession;
}

export interface CredentialRequestJwtVcJson extends AbstractCredentialRequest {
  format: CredentialFormatEnum.jwt_vc_json;
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
}

export interface CredentialRequestJwtVcJsonLdAndLdpVc extends AbstractCredentialRequest {
  format: CredentialFormatEnum.jwt_vc_json_ld | CredentialFormatEnum.ldp_vc;
  credential_definition: IssuerCredentialDefinition;
}

//todo: change this back to CredentialResponse once merged with latest changes from develop
export interface AbstractCredentialResponse {
  format: string;
  credential?: W3CVerifiableCredential;
  acceptance_token?: string;
  c_nonce?: string;
  c_nonce_expires_in?: string;
}

export interface CredentialResponseJwtVcJsonLdAndLdpVc extends AbstractCredentialResponse {
  format: CredentialFormatEnum.jwt_vc_json_ld | CredentialFormatEnum.ldp_vc;
  credential: IVerifiableCredential;
}

export interface IssuerCredentialSubjectDisplay {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  mandatory?: boolean;
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  value_type?: string;
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  display?: NameAndLocale[];
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  order?: string[]; // An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
  [key: string]: {
    mandatory?: boolean;
    value_type?: string;
    display?: NameAndLocale[];
    order?: string[]; // An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
  };
}

export interface IssuerCredentialSubject {
  [key: string]: IssuerCredentialSubjectDisplay;
}

export interface CredentialResponseJwtVcJson {
  credential: string;
}

export interface Grant {
  authorization_code?: GrantAuthorizationCode;
  'urn:ietf:params:oauth:grant-type:pre-authorized_code': GrantUrnIetf;
}

export interface GrantAuthorizationCode {
  issuer_state?: string;
}

export interface GrantUrnIetf {
  'pre-authorized_code': string;
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
  openid4vci_metadata?: OpenID4VCIServerMetadata;
}
