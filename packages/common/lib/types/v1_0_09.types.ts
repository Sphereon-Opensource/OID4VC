import { AbstractAuthorizationDetails, AbstractAuthorizationRequest, CredentialOfferCredential, IssuerCredentialSubject } from './Generic.types';

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-09.html#name-issuance-initiation-request
export interface CredentialOfferV1_0_09 {
  issuer: string;
  credentials: (CredentialOfferCredential | string)[];
  'pre-authorized_code'?: string;
  user_pin_required?: boolean;
  op_state?: string;
}

export interface AuthorizationRequestV1_0_09 extends AbstractAuthorizationRequest {
  op_state?: string;
}

export interface IssuanceInitiationRequestJwtVcJsonV1_0_09 extends CredentialOfferV1_0_09 {
  credentials: CredentialOfferCredential[];
}

export interface AuthorizationDetailsJwtVcJsonV1_0_09 extends AbstractAuthorizationDetails {
  types: string[];
  CredentialSubject?: IssuerCredentialSubject;
}
