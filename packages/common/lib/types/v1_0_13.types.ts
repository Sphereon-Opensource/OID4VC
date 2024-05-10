import {
  CommonCredentialRequest,
  CredentialConfigurationSupported,
  CredentialDataSupplierInput,
  CredentialRequestJwtVcJson,
  CredentialRequestJwtVcJsonLdAndLdpVc,
  CredentialRequestSdJwtVc,
  CredentialSupplierConfig,
  Grant,
  MetadataDisplay,
  NameAndLocale,
  ResponseEncryption,
} from './Generic.types';
import { QRCodeOpts } from './QRCode.types';

export interface IssuerMetadataV1_0_13 {
  issuer?: string;
  credential_endpoint: string; // REQUIRED. URL of the OP's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  credential_configurations_supported: CredentialConfigurationSupported; // REQUIRED. A JSON object containing a list of key value pairs, where the key is a string serving as an abstract identifier of the Credential. This identifier is RECOMMENDED to be collision resistant - it can be globally unique, but does not have to be when naming conflicts are unlikely to arise in a given use case. The value is a JSON object. The JSON object MUST conform to the structure of the Section 11.2.1.
  credential_issuer?: {
    //  OPTIONAL. A JSON object containing display properties for the Credential issuer.
    display: NameAndLocale | NameAndLocale[]; // OPTIONAL. An array of objects, where each object contains display properties of a Credential issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
  };
  authorization_servers?: string[];
  token_endpoint?: string;
  display?: MetadataDisplay[];

  [x: string]: unknown;
}

export type CredentialRequestV1_0_13 = CommonCredentialRequest &
  (CredentialRequestJwtVcJson | CredentialRequestJwtVcJsonLdAndLdpVc | CredentialRequestSdJwtVc);

export interface CredentialOfferV1_0_13 {
  credential_offer?: CredentialOfferPayloadV1_0_13;
  credential_offer_uri?: string;
}

export interface CredentialOfferRESTRequest extends CredentialOfferV1_0_13 {
  baseUri?: string;
  scheme?: string;
  pinLength?: number;
  qrCodeOpts?: QRCodeOpts;
  credentialDataSupplierInput?: CredentialDataSupplierInput;
}

export interface CredentialOfferPayloadV1_0_13 {
  /**
   * REQUIRED. The URL of the Credential Issuer, as defined in Section 11.2.1, from which the Wallet is requested to
   * obtain one or more Credentials. The Wallet uses it to obtain the Credential Issuer's Metadata following the steps
   * defined in Section 11.2.2.
   */
  credential_issuer: string;

  /**
   *  REQUIRED. Array of unique strings that each identify one of the keys in the name/value pairs stored in
   *  the credential_configurations_supported Credential Issuer metadata. The Wallet uses these string values
   *  to obtain the respective object that contains information about the Credential being offered as defined
   *  in Section 11.2.3. For example, these string values can be used to obtain scope values to be used in
   *  the Authorization Request.
   */
  credential_configuration_ids: string[];
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

export interface CredentialIssuerMetadataOptsV1_0_13 {
  credential_endpoint: string; // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  batch_credential_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Batch Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components. If omitted, the Credential Issuer does not support the Batch Credential Endpoint.
  deferred_credential_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint, as defined in Section 9. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Deferred Credential Endpoint.
  notification_endpoint?: string; // OPTIONAL. URL of the Credential Issuer's Notification Endpoint, as defined in Section 10. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Notification Endpoint.
  credential_response_encryption?: ResponseEncryption; // OPTIONAL. Object containing information about whether the Credential Issuer supports encryption of the Credential and Batch Credential Response on top of TLS.
  credential_identifiers_supported?: boolean; // OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning credential_identifiers parameter in the authorization_details Token Response parameter, with true indicating support. If omitted, the default value is false.
  credential_configurations_supported?: Record<string, CredentialConfigurationSupported>; // REQUIRED. A JSON array containing a list of JSON objects, each of them representing metadata about a separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the structure of the Section 10.2.3.1.
  credential_issuer: string; // REQUIRED. The Credential Issuer's identifier.
  authorization_servers?: string[]; // OPTIONAL. Array of strings that identify the OAuth 2.0 Authorization Servers (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  signed_metadata?: string; // OPTIONAL. String that is a signed JWT. This JWT contains Credential Issuer metadata parameters as claims.
  display?: MetadataDisplay[]; //  An array of objects, where each object contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:

  //todo: these two are not mentioned in the spec
  token_endpoint?: string;
  credential_supplier_config?: CredentialSupplierConfig;
}
