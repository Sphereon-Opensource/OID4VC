import { CommonCredentialOfferRequestPayload, CredentialOfferRequestWithBaseUrl } from './CredentialIssuance.types';
import {
  CredentialFormatEnum,
  EndpointMetadata,
  ErrorResponse,
  IssuerCredentialDefinition,
  IssuerCredentialSubject,
  PRE_AUTH_CODE_LITERAL,
} from './Generic.types';

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
  // If the Credential Issuer metadata contains an authorization_server parameter, the authorization detail's locations common data field MUST be set to the Credential Issuer Identifier value.
  locations?: string[];
  [key: string]: any;
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

export enum GrantTypes {
  AUTHORIZATION_CODE = 'authorization_code',
  PRE_AUTHORIZED_CODE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  PASSWORD = 'password',
}

export enum Encoding {
  FORM_URL_ENCODED = 'application/x-www-form-urlencoded',
  UTF_8 = 'UTF-8',
}

export enum ResponseType {
  AUTH_CODE = 'code',
}

export enum CodeChallengeMethod {
  TEXT = 'text',
  SHA256 = 'S256',
}

export interface AuthorizationServerOpts {
  allowInsecureEndpoints?: boolean;
  as?: string; // If not provided the issuer hostname will be used!
  tokenEndpoint?: string; // Allows to override the default '/token' endpoint
  clientId?: string;
}

export interface IssuerOpts {
  issuer: string;
  tokenEndpoint?: string;
  fetchMetadata?: boolean;
}

export interface AccessTokenRequestOpts {
  credentialOffer: CredentialOfferRequestWithBaseUrl;
  asOpts?: AuthorizationServerOpts;
  metadata?: EndpointMetadata;
  codeVerifier?: string; // only required for authorization flow
  code?: string; // only required for authorization flow
  redirectUri?: string; // only required for authorization flow
  pin?: string; // Pin-number. Only used when required
}

export interface AuthorizationRequest {
  response_type: ResponseType.AUTH_CODE;
  client_id: string;
  code_challenge: string;
  code_challenge_method: CodeChallengeMethod;
  authorization_details?: string;
  redirect_uri: string;
  scope?: string;
}

export interface AuthorizationRequestOpts {
  clientId: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  authorizationDetails?: CommonAuthorizationDetails[];
  redirectUri: string;
  scope?: string;
}

export interface AuthorizationGrantResponse {
  grant_type: string;
  code: string;
  scope?: string;
  state?: string;
}

export interface AccessTokenRequest {
  client_id?: string;
  code?: string;
  code_verifier?: string;
  grant_type: GrantTypes;
  'pre-authorized_code': string;
  redirect_uri?: string;
  scope?: string;
  user_pin?: string;
}

export interface OpenIDResponse<T> {
  origResponse: Response;
  successBody?: T;
  errorBody?: ErrorResponse;
}

export interface AccessTokenResponse {
  access_token: string;
  scope?: string;
  token_type?: string;
  expires_in?: number; // in seconds
  c_nonce?: string;
  c_nonce_expires_in?: number; // in seconds
  authorization_pending?: boolean;
  interval?: number; // in seconds
}

export enum AuthzFlowType {
  AUTHORIZATION_CODE_FLOW = 'Authorization Code Flow',
  PRE_AUTHORIZED_CODE_FLOW = 'Pre-Authorized Code Flow',
}

// eslint-disable-next-line @typescript-eslint/no-namespace
export namespace AuthzFlowType {
  export function valueOf(request: CommonCredentialOfferRequestPayload): AuthzFlowType {
    if (request[PRE_AUTH_CODE_LITERAL]) {
      return AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW;
    }
    return AuthzFlowType.AUTHORIZATION_CODE_FLOW;
  }
}
