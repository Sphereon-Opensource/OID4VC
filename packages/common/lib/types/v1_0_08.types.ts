import { CredentialSupportedBrief, Display, IssuerCredentialSubject } from './Generic.types';
export interface IssuerMetadataV1_0_08 {
  issuer?: string;
  credential_endpoint: string;
  credentials_supported: CredentialSupportedTypeV1_0_08;
  credential_issuer?: {
    display: Display | Display[];
  };
  authorization_server?: string;
  token_endpoint?: string;
  display?: Display[];
  [x: string]: unknown;
}

export interface CredentialSupportedTypeV1_0_08 {
  [credentialType: string]: CredentialSupportedV1_0_08;
}

export interface CredentialSupportedV1_0_08 {
  display?: Display[];
  formats: {
    [credentialFormat: string]: CredentialSupportedBrief;
  };
  claims?: IssuerCredentialSubject;
}
