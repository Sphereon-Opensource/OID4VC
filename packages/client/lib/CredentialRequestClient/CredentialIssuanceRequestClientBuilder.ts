import { AccessTokenResponse, OpenID4VCIServerMetadata } from '@sphereon/openid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialRequestClient } from './CredentialRequestClient';

export interface CredentialIssuanceRequestClientBuilder {
  withCredentialEndpointFromMetadata(metadata: OpenID4VCIServerMetadata): CredentialIssuanceRequestClientBuilder;

  withCredentialEndpoint(credentialEndpoint: string): CredentialIssuanceRequestClientBuilder;

  withCredentialType(credentialType: string | string[]): CredentialIssuanceRequestClientBuilder;

  withFormat(format: CredentialFormat | CredentialFormat[]): CredentialIssuanceRequestClientBuilder;

  withToken(accessToken: string): CredentialIssuanceRequestClientBuilder;

  withTokenFromResponse(response: AccessTokenResponse): CredentialIssuanceRequestClientBuilder;

  build(): CredentialRequestClient;
}
