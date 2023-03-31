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

export interface LogoAndColor {
  logo?: CredentialLogo;
  background_color?: string;
  text_color?: string;
}

export type Display = NameAndLocale & LogoAndColor & { [key: string]: string };

export interface IssuerMetadata {
  credential_endpoint: string;
  batch_credential_endpoint?: string;
  credentials_supported: CredentialIssuerMetadataSupportedCredentials[];
  credential_issuer: Display;
}

export interface CredentialIssuerMetadataSupportedCredentials {
  format: CredentialFormatEnum | string;
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

export interface CredentialOfferCredential {
  format: CredentialFormatEnum;
}

export interface CredentialOfferCredentialJwtVcJson extends CredentialOfferCredential {
  format: CredentialFormatEnum.jwt_vc_json;
  types: string[];
}

export interface IssuerCredentialDefinition {
  '@context': ICredentialContextType[];
  types: string[];
  credentialSubject: IssuerCredentialSubject;
}

export interface CommonAuthorizationRequest {
  response_type: ResponseType.AUTH_CODE;
  client_id: string;
  code_challenge: string;
  code_challenge_method: CodeChallengeMethod;
  redirect_uri: string;
  scope?: string;
  authorization_details?: CommonAuthorizationDetails[];
  wallet_issuer?: string;
  user_hint?: string;
}

export interface AuthorizationRequestJwtVcJson extends CommonAuthorizationRequest {
  authorization_details?: AuthorizationDetailsJwtVcJson[];
}

export interface AuthorizationRequestJwtVcJsonLdAndLdpVc extends CommonAuthorizationRequest {
  authorization_details?: AuthorizationDetailsJwtVcJsonLdAndLdpVc[];
}

export interface CommonAuthorizationDetails {
  type: 'openid_credential' | string;
  format: CredentialFormatEnum;
}

export interface AuthorizationDetailsJwtVcJson extends CommonAuthorizationDetails {
  format: CredentialFormatEnum.jwt_vc_json;
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
}

export interface AuthorizationDetailsJwtVcJsonLdAndLdpVc extends CommonAuthorizationDetails {
  format: CredentialFormatEnum.ldp_vc | CredentialFormatEnum.jwt_vc_json_ld;
  types: string[];
  credential_definition: IssuerCredentialDefinition;
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

export interface CommonCredentialRequest {
  format: string;
  proof?: ProofOfPossession;
}

export interface CredentialRequestJwtVcJson extends CommonCredentialRequest {
  format: CredentialFormatEnum.jwt_vc_json;
  types: string[];
  credentialSubject?: IssuerCredentialSubject;
}

export interface CredentialRequestJwtVcJsonLdAndLdpVc extends CommonCredentialRequest {
  format: CredentialFormatEnum.jwt_vc_json_ld | CredentialFormatEnum.ldp_vc;
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
  format: CredentialFormatEnum.jwt_vc_json_ld | CredentialFormatEnum.ldp_vc;
  credential: IVerifiableCredential;
}

export type IssuerCredentialSubjectDisplay = CredentialSubjectDisplay & Record<string, CredentialSubjectDisplay>

export interface CredentialSubjectDisplay {
  mandatory?: boolean;
  value_type?: string;
  display?: NameAndLocale[];
  order?: string[]; // An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
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
