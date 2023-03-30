import { AbstractAuthorizationRequest, CredentialFormatEnum, CredentialOfferCredential, Grant, IssuerCredentialDefinition } from './Generic.types';

export interface CredentialOfferV1_0_11 {
  credential_offer?: InnerCredentialOfferV1_0_11;
  credential_offer_uri?: string;
}

export interface InnerCredentialOfferV1_0_11 {
  credential_issuer: string;
  //fixme: @nklomp, I've made this optional because in the annex E's example, we don't see the credentials property, but we see credential_definition property which I guess does the same thing. I've already asked about this in https://bitbucket.org/openid/connect/issues/1875/differences-between-spec-and-examples-in
  credentials?: (CredentialOfferCredential | string)[];
  grants?: Grant;
}

export interface AuthorizationRequestV1_0_11 extends AbstractAuthorizationRequest {
  issuer_state?: string;
}

export interface CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11 extends InnerCredentialOfferV1_0_11 {
  credential_definition: IssuerCredentialDefinition;
}

export interface CredentialOfferJwtVcJsonV1_0_11 extends InnerCredentialOfferV1_0_11 {
  credentials: (
    | {
        format: CredentialFormatEnum.jwt_vc_json;
        types: string[];
      }
    | string
  )[];
}
