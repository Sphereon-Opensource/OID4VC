import { CommonAuthorizationRequest } from './Authorization.types';
import { CredentialOfferPayload } from './CredentialIssuance.types';
import { CredentialOfferCredentialJwtVcJson } from './Generic.types';

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

export function isAuthorizationRequestV1_0_09(request: CommonAuthorizationRequest): boolean {
  return request && 'op_state' in request;
}

export function isCredentialOfferV1_0_09(request: CredentialOfferPayload): boolean {
  return request && ('issuer' in request || 'op_state' in request);
}
