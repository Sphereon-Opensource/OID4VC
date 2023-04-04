import { AuthorizationDetailsJwtVcJson, CommonAuthorizationRequest } from './Authorization.types';
import { CredentialOfferPayload } from './CredentialIssuance.types';
import { CredentialOfferCredential, Grant, IssuerCredentialDefinition } from './Generic.types';

export interface CredentialOfferV1_0_11 {
  credential_offer?: CommonCredentialOfferPayloadV1_0_11;
  credential_offer_uri?: string;
}

export interface CommonCredentialOfferPayloadV1_0_11 {
  credential_issuer: string;
  //fixme: @nklomp, I've made this optional because in the annex E's example, we don't see the credentials property, but we see credential_definition property which I guess does the same thing. I've already asked about this in https://bitbucket.org/openid/connect/issues/1875/differences-between-spec-and-examples-in
  credentials?: (CredentialOfferCredential | string)[];
  grants?: Grant;
}

export interface CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11 extends CommonCredentialOfferPayloadV1_0_11 {
  credential_definition: IssuerCredentialDefinition;
}

export interface CredentialOfferJwtVcJsonV1_0_11 extends CommonCredentialOfferPayloadV1_0_11 {
  credentials: (CredentialOfferCredential | string)[];
}

export type CredentialOfferPayloadV1_0_11 = CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11 | CredentialOfferJwtVcJsonV1_0_11;

export interface AuthorizationRequestV1_0_11 extends AuthorizationDetailsJwtVcJson, AuthorizationDetailsJwtVcJson {
  issuer_state?: string;
}

export function isAuthorizationRequestV1_0_11(request: CommonAuthorizationRequest): boolean {
  return request && 'issuer_state' in request;
}

export function isCredentialOfferV1_0_11(request: CredentialOfferPayload | CredentialOfferV1_0_11): boolean {
  return request && ('credential_offer' in request || 'credential_offer_uri' in request || 'credential_issuer' in request);
}
