import { IssuanceInitiationRequestPayload } from './CredentialIssuance.types';
import { PRE_AUTH_CODE_LITERAL } from './Generic.types';

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

export interface AuthorizationServerOpts {
  as?: string; // If not provided the issuer hostname will be used!
  tokenEndpoint?: string; // Allows to override the default '/token' endpoint
  clientId?: string; // If not provided a random clientId will be generated
}

export interface IssuerTokenEndpointOpts {
  issuer: string;
  tokenEndpoint?: string;
}

export interface AccessTokenRequestOpts {
  asOpts?: AuthorizationServerOpts;
  pin?: string; // Pin-number. Only used when required
}

export interface AuthorizationRequest {
  response_type: ResponseType.AUTH_CODE;
  client_id: string;
  redirect_uri: string;
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
  code_verifier?: string;
  grant_type: GrantTypes;
  'pre-authorized_code': string;
  redirect_uri?: string;
  scope?: string;
  user_pin?: string;
}

export interface AccessTokenResponse {
  access_token: string;
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
  export function valueOf(request: IssuanceInitiationRequestPayload): AuthzFlowType {
    if (request[PRE_AUTH_CODE_LITERAL]) {
      return AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW;
    }
    return AuthzFlowType.AUTHORIZATION_CODE_FLOW;
  }
}
