import {
  AccessTokenRequest,
  AccessTokenResponse,
  AuthorizationServerOpts,
  CredentialOfferAccessTokenRequestOpts_V11,
  EndpointMetadata,
  IssuanceInitiationAccessTokenRequestOpts,
  IssuerOpts,
  OpenIDResponse,
} from '@sphereon/openid4vci-common';

import { IssuanceInitiationClient } from '../CredentialOffer';

import { AccessTokenClient } from './AccessTokenClient';

// noinspection JSUnusedLocalSymbols
export class CredentialOfferAccessTokenClient implements AccessTokenClient {
  getAccessTokenRequest = (
    issuanceInitiationClient: IssuanceInitiationClient,
    metadata: EndpointMetadata,
    pin?: string,
    clientId?: string,
    codeVerifier?: string,
    code?: string,
    redirectUri?: string
  ): IssuanceInitiationAccessTokenRequestOpts => {
    throw Error('Not yet implemented');
  };

  public async acquireAccessToken(
    credentialOfferAccessTokenRequestOpts: CredentialOfferAccessTokenRequestOpts_V11
  ): Promise<OpenIDResponse<AccessTokenResponse>> {
    throw new Error('Not yet implemented');
  }

  public async createAccessTokenRequest(
    credentialOfferAccessTokenRequestOpts: CredentialOfferAccessTokenRequestOpts_V11
  ): Promise<AccessTokenRequest> {
    throw new Error('Not yet implemented');
  }

  public static determineTokenURL({
    asOpts,
    issuerOpts,
    metadata,
  }: {
    asOpts?: AuthorizationServerOpts;
    issuerOpts?: IssuerOpts;
    metadata?: EndpointMetadata;
  }): string {
    throw new Error('Not yet implemented');
  }
}
