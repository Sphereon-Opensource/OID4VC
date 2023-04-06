import { CredentialSupportedBrief, Display, IssuerCredentialSubject } from './Generic.types';
export interface IssuerMetadataV1_0_08 {
  credential_endpoint: string;
  credentials_supported: CredentialSupportedTypeV1_0_08;
  credential_issuer: string;
  authorization_server?: string;
  token_endpoint?: string;
  display?: Display[];
}

export interface CredentialSupportedTypeV1_0_08 {
  [credentialType: string]: CredentialSupportedV1_0_08;
}

export interface CredentialSupportedV1_0_08 {
  display?: Display[];
  formats: {
    [credentialFormat: string]: CredentialSupportedBrief;
  };
  claims: IssuerCredentialSubject;
}
