import { CommonAuthorizationDetails, CommonAuthorizationRequest, CredentialOfferCredentialJwtVcJson } from './Generic.types';
import { CredentialOfferV1_0_11 } from './v1_0_11.types';

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-09.html#name-issuance-initiation-request
export interface CredentialOfferV1_0_09 {
  issuer: string; //(url) REQUIRED The issuer URL of the Credential issuer, the Wallet is requested to obtain one or more Credentials from.
  credential_type: string[] | string; //(url) REQUIRED A JSON string denoting the type of the Credential the Wallet shall request
  credentials: CredentialOfferCredentialJwtVcJson[];
  'pre-authorized_code'?: string; //CONDITIONAL the code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short-lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean | string; //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
  op_state?: string; //(JWT) OPTIONAL String value created by the Credential Issuer and opaque to the Wallet that is used to bind the subsequent authentication request with the Credential Issuer to a context set up during previous steps
}

export interface AuthorizationRequestV1_0_09 extends CommonAuthorizationRequest {
  op_state?: string;
}

export interface AuthorizationDetailsJwtVcJsonV1_0_09 extends CommonAuthorizationDetails {
  // If the Credential Issuer metadata contains an authorization_server parameter, the authorization detail's locations common data field MUST be set to the Credential Issuer Identifier value.
  locations?: string[];
  types: string[];
  // fixme: we don't support this property in the current flow for jff. so I commented it out
  //CredentialSubject?: IssuerCredentialSubject;
  [key: string]: unknown;
}

export function isAuthorizationRequestV1_0_09(request: CommonAuthorizationRequest): boolean {
  return request && 'op_state' in request;
}

export function isCredentialOfferV1_0_09(request: CredentialOfferV1_0_09 | CredentialOfferV1_0_11): boolean {
  return request && 'issuer' in request && 'op_state' in request;
}
