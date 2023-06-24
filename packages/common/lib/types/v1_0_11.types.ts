import { AuthorizationDetailsJwtVcJson, CommonAuthorizationRequest } from './Authorization.types';
import {
  CommonCredentialRequest,
  CredentialDataSupplierInput,
  CredentialOfferFormat,
  CredentialRequestJwtVcJson,
  CredentialRequestJwtVcJsonLdAndLdpVc,
  Grant,
  IssuerCredentialDefinition,
} from './Generic.types';

export interface CredentialOfferV1_0_11 {
  credential_offer?: CredentialOfferPayloadV1_0_11;
  credential_offer_uri?: string;
}

export interface CredentialOfferRESTRequest extends CredentialOfferV1_0_11 {
  baseUri?: string;
  scheme?: string;
  pinLength?: number;
  credentialDataSupplierInput?: CredentialDataSupplierInput;
}

export interface CommonCredentialOfferPayloadV1_0_11 {
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
  credentials: (CredentialOfferFormat | string)[];
  /**
   * OPTIONAL. A JSON object indicating to the Wallet the Grant Types the Credential Issuer's AS is prepared
   * to process for this credential offer. Every grant is represented by a key and an object.
   * The key value is the Grant Type identifier, the object MAY contain parameters either determining the way
   * the Wallet MUST use the particular grant and/or parameters the Wallet MUST send with the respective request(s).
   * If grants is not present or empty, the Wallet MUST determine the Grant Types the Credential Issuer's AS supports
   * using the respective metadata. When multiple grants are present, it's at the Wallet's discretion which one to use.
   */
  grants?: Grant;
}

export interface CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11 extends CommonCredentialOfferPayloadV1_0_11 {
  /**
   * REQUIRED. JSON object containing (and isolating) the detailed description of the credential type.
   * This object MUST be processed using full JSON-LD processing. It consists of the following sub-claims:
   *   - @context: REQUIRED. JSON array as defined in Appendix E.1.3.2
   *   - types: REQUIRED. JSON array as defined in Appendix E.1.3.2.
   *            This claim contains the type values the Wallet shall request in the subsequent Credential Request
   */
  credential_definition: IssuerCredentialDefinition;
}

export type CredentialOfferJwtVcJsonV1_0_11 = CommonCredentialOfferPayloadV1_0_11;

export type CredentialOfferPayloadV1_0_11 = CommonCredentialOfferPayloadV1_0_11 &
  (CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11 | CredentialOfferJwtVcJsonV1_0_11);

export type CredentialRequestV1_0_11 = CommonCredentialRequest & (CredentialRequestJwtVcJson | CredentialRequestJwtVcJsonLdAndLdpVc);

export interface AuthorizationRequestV1_0_11 extends AuthorizationDetailsJwtVcJson, AuthorizationDetailsJwtVcJson {
  issuer_state?: string;
}

// todo https://sphereon.atlassian.net/browse/VDX-185
export function isAuthorizationRequestV1_0_11(request: CommonAuthorizationRequest): boolean {
  return request && 'issuer_state' in request;
}
