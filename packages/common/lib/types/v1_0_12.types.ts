import { CommonCredentialRequest, CredentialRequestJwtVcJson, CredentialRequestJwtVcJsonLdAndLdpVc, CredentialRequestSdJwtVc } from './Generic.types';

export type CredentialRequestV1_0_12 = CommonCredentialRequest &
  (CredentialRequestJwtVcJson | CredentialRequestJwtVcJsonLdAndLdpVc | CredentialRequestSdJwtVc);
