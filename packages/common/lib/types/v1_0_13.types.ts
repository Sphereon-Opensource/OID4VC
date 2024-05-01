import {
  CommonCredentialRequest, CredentialConfigurationSupported, CredentialDataSupplierInput,
  CredentialRequestJwtVcJson,
  CredentialRequestJwtVcJsonLdAndLdpVc,
  CredentialRequestSdJwtVc, Grant, MetadataDisplay,
  NameAndLocale
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
