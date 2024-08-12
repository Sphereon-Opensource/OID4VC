import { AuthorizationDetailsJwtVcJson, AuthorizationServerOpts, CommonAuthorizationRequest } from './Authorization.types';
import { UniformCredentialOffer, UniformCredentialOfferRequest } from './CredentialIssuance.types';
import {
  CommonCredentialRequest,
  CredentialDataSupplierInput,
  CredentialIssuerMetadataOpts,
  CredentialOfferFormatV1_0_11,
  CredentialRequestJwtVcJson,
  CredentialRequestJwtVcJsonLdAndLdpVc,
  CredentialRequestSdJwtVc,
  Grant,
} from './Generic.types';
import { QRCodeOpts } from './QRCode.types';
import { AuthorizationServerMetadata, AuthorizationServerType, EndpointMetadata } from './ServerMetadata';
import { IssuerMetadataV1_0_08 } from './v1_0_08.types';

export interface AccessTokenRequestOptsV1_0_11 {
  credentialOffer?: UniformCredentialOffer;
  credentialIssuer?: string;
  asOpts?: AuthorizationServerOpts;
  metadata?: EndpointMetadata;
  codeVerifier?: string; // only required for authorization flow
  code?: string; // only required for authorization flow
  redirectUri?: string; // only required for authorization flow
  pin?: string; // Pin-number. Only used when required
}

export interface CredentialOfferV1_0_11 {
  credential_offer?: CredentialOfferPayloadV1_0_11;
  credential_offer_uri?: string;
}

export interface CredentialOfferRESTRequestV1_0_11 extends CredentialOfferV1_0_11 {
  baseUri?: string;
  scheme?: string;
  pinLength?: number;
  qrCodeOpts?: QRCodeOpts;
  credentialDataSupplierInput?: CredentialDataSupplierInput;
}

export interface CredentialOfferRequestWithBaseUrlV1_0_11 extends UniformCredentialOfferRequest {
  scheme: string;
  clientId?: string;
  baseUrl: string;
  userPinRequired: boolean;
  issuerState?: string;
  preAuthorizedCode?: string;
}

export interface CredentialOfferPayloadV1_0_11 {
  /**
   * REQUIRED. The URL of the Credential Issuer, the Wallet is requested to obtain one or more Credentials from.
   */
  credential_issuer: string;

  /**
   * REQUIRED. A JSON array, where every entry is a JSON object or a JSON string. If the entry is an object,
   * the object contains the data related to a certain credential type the Wallet MAY request.
   * Each object MUST contain a format Claim determining the format of the credential to be requested and
   * further parameters characterising the type of the credential to be requested as defined in Appendix E.
   * If the entry is a string, the string value MUST be one of the id values in one of the objects in the
   * credentials_supported Credential Issuer metadata parameter.
   * When processing, the Wallet MUST resolve this string value to the respective object.
   */
  credentials: (CredentialOfferFormatV1_0_11 | string)[];
  /**
   * OPTIONAL. A JSON object indicating to the Wallet the Grant Types the Credential Issuer's AS is prepared
   * to process for this credential offer. Every grant is represented by a key and an object.
   * The key value is the Grant Type identifier, the object MAY contain parameters either determining the way
   * the Wallet MUST use the particular grant and/or parameters the Wallet MUST send with the respective request(s).
   * If grants is not present or empty, the Wallet MUST determine the Grant Types the Credential Issuer's AS supports
   * using the respective metadata. When multiple grants are present, it's at the Wallet's discretion which one to use.
   */
  grants?: Grant;

  /**
   * Some implementations might include a client_id in the offer. For instance EBSI in a same-device flow. (Cross-device tucks it in the state JWT)
   */
  client_id?: string;
}

export type CredentialRequestV1_0_11 = CommonCredentialRequest &
  (CredentialRequestJwtVcJson | CredentialRequestJwtVcJsonLdAndLdpVc | CredentialRequestSdJwtVc);

export interface CredentialIssuerMetadataV1_0_11 extends CredentialIssuerMetadataOpts, Partial<AuthorizationServerMetadata> {
  authorization_servers?: string[]; // OPTIONAL. Array of strings that identify the OAuth 2.0 Authorization Servers (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  credential_endpoint: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  credential_response_encryption_alg_values_supported?: string; // OPTIONAL. Array containing a list of the JWE [RFC7516] encryption algorithms (alg values) [RFC7518] supported by the Credential and/or Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].
  credential_response_encryption_enc_values_supported?: string; //OPTIONAL. Array containing a list of the JWE [RFC7516] encryption algorithms (enc values) [RFC7518] supported by the Credential and/or Batch Credential Endpoint to encode the Credential or Batch Credential Response in a JWT [RFC7519].
  require_credential_response_encryption?: boolean; //OPTIONAL. Boolean value specifying whether the Credential Issuer requires additional encryption on top of TLS for the Credential Response and expects encryption parameters to be present in the Credential Request and/or Batch Credential Request, with true indicating support. When the value is true, credential_response_encryption_alg_values_supported parameter MUST also be provided. If omitted, the default value is false.
  credential_identifiers_supported?: boolean; // OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning credential_identifiers parameter in the authorization_details Token Response parameter, with true indicating support. If omitted, the default value is false.
}

export interface AuthorizationRequestV1_0_11 extends AuthorizationDetailsJwtVcJson, AuthorizationDetailsJwtVcJson {
  issuer_state?: string;
}

// todo https://sphereon.atlassian.net/browse/VDX-185
export function isAuthorizationRequestV1_0_11(request: CommonAuthorizationRequest): boolean {
  return request && 'issuer_state' in request;
}

export interface EndpointMetadataResultV1_0_11 extends EndpointMetadata {
  // The EndpointMetadata are snake-case so they can easily be used in payloads/JSON.
  // The values below should not end up in requests/responses directly, so they are using our normal CamelCase convention
  authorizationServerType: AuthorizationServerType;
  authorizationServerMetadata?: AuthorizationServerMetadata;
  credentialIssuerMetadata?: Partial<AuthorizationServerMetadata> & IssuerMetadataV1_0_08;
}
