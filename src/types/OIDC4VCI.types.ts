export enum GrantTypes {
  AUTHORIZATION_CODE = 'authorization_code',
  PRE_AUTHORIZED = 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  PASSWORD = 'password',
}

export enum Encoding {
  FORM_URL_ENCODED = 'application/x-www-form-urlencoded',
  UTF_8 = 'UTF-8',
}

export enum ResponseType {
  AUTH_CODE = 'code',
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
  grant_type: string;
  pre_authorized_code: string;
  redirect_uri?: string;
  scope?: string;
  user_pin?: bigint;
  user_pin_required?: boolean;
}

export interface AccessTokenResponse {
  username?: string;
  password?: string;
  access_token?: string;
  token_type?: string;
  expires_in?: bigint; // in seconds
  c_nonce?: string;
  c_nonce_expires_in?: bigint; // in seconds
  authorization_pending?: boolean;
  interval?: bigint; // in seconds
}

export interface ErrorResponse extends Response {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}
