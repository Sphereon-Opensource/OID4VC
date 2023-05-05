import { CredentialOfferPayload, CredentialOfferRequestWithBaseUrl } from './CredentialIssuance.types';
import {
  CredentialFormat,
  EndpointMetadata,
  ErrorResponse,
  IssuerCredentialDefinition,
  IssuerCredentialSubject,
  PRE_AUTH_CODE_LITERAL,
} from './Generic.types';

export interface CommonAuthorizationRequest {
  /**
   * REQUIRED.  Value MUST be set to "code". for Authorization Code Grant
   */
  response_type: ResponseType.AUTH_CODE;
  /**
   * The authorization server issues the registered client a client
   *    identifier -- a unique string representing the registration
   *    information provided by the client.
   */
  client_id: string;
  /**
   * If the "code_challenge_method" from Section 4.3 was "S256", the
   *    received "code_verifier" is hashed by SHA-256, base64url-encoded, and
   *    then compared to the "code_challenge", i.e.:
   *    BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
   *
   * If the "code_challenge_method" from Section 4.3 was "plain", they are
   *    compared directly, i.e.:
   *    code_verifier == code_challenge.
   */
  code_challenge: string;
  /**
   * value must be set either to "S256" or a value defined by a cryptographically secure
   */
  code_challenge_method: CodeChallengeMethod;
  /**
   * The redirection endpoint URI MUST be an absolute URI as defined by: absolute-URI  = scheme ":" hier-part [ "?" query ]
   */
  redirect_uri: string;
  /**
   * The value of the scope parameter is expressed as a list of space-delimited, case-sensitive strings.
   */
  scope?: string;
  /**
   * There are two possible ways to request issuance of a specific Credential type in an Authorization Request.
   * One way is to use of the authorization_details request parameter as defined in [I-D.ietf-oauth-rar]
   * with one or more authorization details objects of type openid_credential Section 5.1.1.
   * (The other is through the use of scopes as defined in Section 5.1.2.)
   */
  authorization_details?: AuthorizationDetails[] | AuthorizationDetails;
  /**
   * OPTIONAL. JSON string containing the Wallet's OpenID Connect issuer URL. The Credential Issuer will use the discovery process as defined in
   * [SIOPv2] to determine the Wallet's capabilities and endpoints. RECOMMENDED in Dynamic Credential Request.
   */
  wallet_issuer?: string;
  /**
   * OPTIONAL. JSON string containing an opaque user hint the Wallet MAY use in subsequent callbacks to optimize the user's experience.
   * RECOMMENDED in Dynamic Credential Request.
   */
  user_hint?: string;
  /**
   * OPTIONAL. String value identifying a certain processing context at the Credential Issuer. A value for this parameter is typically passed in
   * an issuance initation request from the Credential Issuer to the Wallet (see (Section 4.1). This request parameter is used to pass the
   * issuer_state value back to the Credential Issuer.
   */
  issuer_state?: string;
}

/**
 * string type added for conformity with our previous code in the client
 */
export type AuthorizationDetails = AuthorizationDetailsJwtVcJson | AuthorizationRequestJwtVcJsonLdAndLdpVc | string;

export type AuthorizationRequest = AuthorizationRequestJwtVcJson | AuthorizationDetailsJwtVcJsonLdAndLdpVc;

export interface AuthorizationRequestJwtVcJson extends CommonAuthorizationRequest {
  authorization_details?: AuthorizationDetailsJwtVcJson[];
}

export interface AuthorizationRequestJwtVcJsonLdAndLdpVc extends CommonAuthorizationRequest {
  authorization_details?: AuthorizationDetailsJwtVcJsonLdAndLdpVc[];
}

export interface CommonAuthorizationDetails {
  /**
   * REQUIRED. JSON string that determines the authorization details type.
   * MUST be set to openid_credential for the purpose of this specification.
   */
  type: 'openid_credential' | string;
  /**
   * REQUIRED. JSON string representing the format in which the Credential is requested to be issued.
   * This Credential format identifier determines further claims in the authorization details object
   * specifically used to identify the Credential type to be issued. This specification defines
   * Credential Format Profiles in Appendix E.
   */
  format: CredentialFormat;
  /**
   * If the Credential Issuer metadata contains an authorization_server parameter,
   * the authorization detail's locations common data field MUST be set to the Credential Issuer Identifier value.
   */
  locations?: string[];
  types: string[]; // This claim contains the type values the Wallet requests authorization for at the issuer.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

export interface AuthorizationDetailsJwtVcJson extends CommonAuthorizationDetails {
  /**
   * A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential.
   * The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the
   * verifiable credential to be issued. This object indicates the claims the Wallet would like to turn up in the
   * credential to be issued.
   */
  credentialSubject?: IssuerCredentialSubject;
}

export interface AuthorizationDetailsJwtVcJsonLdAndLdpVc extends CommonAuthorizationDetails {
  /**
   * REQUIRED. JSON object containing (and isolating) the detailed description of the credential type.
   * This object MUST be processed using full JSON-LD processing. It consists of the following sub-claims:
   *   - @context: REQUIRED. JSON array as defined in Appendix E.1.3.2
   *   - types: REQUIRED. JSON array as defined in Appendix E.1.3.2.
   *            This claim contains the type values the Wallet shall request in the subsequent Credential Request
   */
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

export interface AuthorizationRequestOpts {
  clientId: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  authorizationDetails?: AuthorizationDetails[];
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
  export function valueOf(request: CredentialOfferPayload): AuthzFlowType {
    if (PRE_AUTH_CODE_LITERAL in request) {
      return AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW;
    }
    return AuthzFlowType.AUTHORIZATION_CODE_FLOW;
  }
}

export interface PushedAuthorizationResponse {
  request_uri: string;
  expires_in: number;
}
