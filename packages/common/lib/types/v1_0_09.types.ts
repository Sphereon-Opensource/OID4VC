import { CommonAuthorizationRequest } from './Authorization.types';
import { CredentialOfferFormat } from './Generic.types';

export interface CredentialOfferV1_0_09 {
  credential_offer: CredentialOfferPayloadV1_0_09;
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-09.html#name-issuance-initiation-request
export interface CredentialOfferPayloadV1_0_09 {
  /**
   * REQUIRED. The URL of the Credential Issuer, the Wallet is requested to obtain one or more Credentials from.
   */
  issuer: string;
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
  'pre-authorized_code'?: string; //CONDITIONAL the code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short-lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean | string; //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
  op_state?: string; //(JWT) OPTIONAL String value created by the Credential Issuer and opaque to the Wallet that is used to bind the subsequent authentication request with the Credential Issuer to a context set up during previous steps
}

export interface AuthorizationRequestV1_0_09 extends CommonAuthorizationRequest {
  op_state?: string;
}

// todo https://sphereon.atlassian.net/browse/VDX-185
export function isAuthorizationRequestV1_0_09(request: CommonAuthorizationRequest): boolean {
  return request && 'op_state' in request;
}
