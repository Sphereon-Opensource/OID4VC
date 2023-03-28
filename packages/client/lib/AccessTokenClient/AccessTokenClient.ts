import { AccessTokenRequestOpts, AccessTokenResponse, EndpointMetadata, OpenIDResponse } from '@sphereon/openid4vci-common';

import { CredentialIssuanceClient } from '../CredentialOffer';

export interface AccessTokenClient {
  getAccessTokenRequest(
    credentialIssuanceClient: CredentialIssuanceClient,
    metadata: EndpointMetadata,
    pin?: string,
    clientId?: string,
    codeVerifier?: string,
    code?: string,
    redirectUri?: string
  ): AccessTokenRequestOpts;

  acquireAccessToken(accessTokenRequestOpts: AccessTokenRequestOpts): Promise<OpenIDResponse<AccessTokenResponse>>;
}
