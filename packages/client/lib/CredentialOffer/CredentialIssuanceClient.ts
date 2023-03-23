import { OpenId4VCIVersion } from '@sphereon/openid4vci-common';

export interface CredentialIssuanceClient {
  readonly _version: OpenId4VCIVersion;

  getIssuer(): string;

  assertIssuerData(): void;

  getCredentialTypes(): string[];
}
