export enum GrantTypes {
  AUTHORIZATION_CODE = 'authorization_code',
  PRE_AUTHORIZED = 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  PASSWORD = 'password',
}

export enum Encoding {
  ENCODING = 'application/x-www-form-urlencoded',
  UTF_8 = 'UTF-8',
}

export enum TokenType {
  BEARER = 'bearer',
}

export enum ClientType {
  CONFIDENTIAL = 'confidential',
  PUBLIC = 'public',
}

export class ClientProfile {
  public static readonly WEB = new ClientProfile('web', ClientType.CONFIDENTIAL);
  public static readonly USER_AGENT_BASED = new ClientProfile('user-agent-based', ClientType.CONFIDENTIAL);
  public static readonly NATIVE = new ClientProfile('native', ClientType.CONFIDENTIAL);

  private readonly _profile: string;
  private readonly _clientType: ClientType;

  private constructor(public readonly clientProfile: string, public readonly clientzType: ClientType) {
    this._profile = clientProfile;
    this._clientType = clientzType;
  }

  public get profile(): string {
    return this._profile;
  }

  public get clientType(): string {
    return this._clientType;
  }
}

export interface Request {
  requestType: string;
}

export interface Response {
  responseType: string;
}

export enum ExchangeStep {
  AUTHORIZATION = 'authorization',
  GET_ACCESS_TOKEN = 'get_access_token',
  GET_CREDENTIAL = 'get_credential',
}

export interface AuthorizationExchangeMetaData {
  exchanges: Map<ExchangeStep, AuthorizationExchange>; //   tokenEndPoint: URL

  isAuthenticatingWithAuthorizationServer: boolean;
  client_type?: ClientType;
}

export interface AuthorizationExchange {
  url: URL;
  request: Request;
  response: Response;
}

export enum ResponseType {
  AUTH_CODE = 'code',
}

export interface AuthorizationRequest extends Request {
  response_type: ResponseType.AUTH_CODE;
  client_id: string;
  redirect_uri: string;
  scope?: string;
}

export interface AuthorizationGrantResponse extends Response {
  grant_type: string;
  code: string;
  scope?: string;
  state?: string;
}

export interface AccessTokenIssuanceRequest extends Request {
  client_id?: string;
  code_verifier?: string;
  grant_type: string;
  'pre-authorized_code': string;
  redirect_uri?: string;
  scope?: string;
  user_pin?: bigint;
  user_pin_required?: boolean;
}

export interface AccessTokenIssuanceResponse extends Response {
  username?: string;
  password?: string;
  access_token?: string;
  token_type?: TokenType;
  expires_in?: bigint; // in seconds
  c_nonce?: string;
  c_nonce_expires_in?: bigint; // in seconds
  authorization_pending?: boolean;
  interval?: bigint; // in seconds
}

export type CredentialIssuanceRequest = Request;

export type CredentialIssuanceResponse = Response;

export interface ErrorResponse extends Response {
  error: string;
  error_description?: string;
  error_uri?: string;
  state?: string;
}
