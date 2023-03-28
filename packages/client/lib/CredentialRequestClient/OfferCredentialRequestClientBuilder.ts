import {
  AccessTokenResponse,
  CredentialOfferWithBaseURL,
  EndpointMetadata,
  IssuanceInitiationWithBaseUrl,
  OpenID4VCIServerMetadata,
} from '@sphereon/openid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialIssuanceRequestClientBuilder } from './CredentialIssuanceRequestClientBuilder';
import { CredentialRequestClient } from './CredentialRequestClient';

// noinspection JSUnusedLocalSymbols
export class OfferCredentialRequestClientBuilder implements CredentialIssuanceRequestClientBuilder {
  public static fromURI({ uri, metadata }: { uri: string; metadata?: EndpointMetadata }): OfferCredentialRequestClientBuilder {
    throw new Error('Not yet implemented');
  }

  public static fromCredentialOffer({
    credentialOfferWithBaseURL,
    metadata,
  }: {
    credentialOfferWithBaseURL: CredentialOfferWithBaseURL;
    metadata?: EndpointMetadata;
  }): OfferCredentialRequestClientBuilder {
    throw new Error('Not yet implemented');
  }

  public static fromIssuanceInitiation({
    initiation,
    metadata,
  }: {
    initiation: IssuanceInitiationWithBaseUrl;
    metadata?: EndpointMetadata;
  }): OfferCredentialRequestClientBuilder {
    throw new Error('Not yet implemented');
  }

  public withCredentialEndpointFromMetadata(metadata: OpenID4VCIServerMetadata): OfferCredentialRequestClientBuilder {
    throw new Error('Not yet implemented');
  }

  public withCredentialEndpoint(credentialEndpoint: string): OfferCredentialRequestClientBuilder {
    throw new Error('Not yet implemented');
  }

  public withCredentialType(credentialType: string | string[]): OfferCredentialRequestClientBuilder {
    throw new Error('Not yet implemented');
  }

  public withFormat(format: CredentialFormat | CredentialFormat[]): OfferCredentialRequestClientBuilder {
    throw new Error('Not yet implemented');
  }

  public withToken(accessToken: string): OfferCredentialRequestClientBuilder {
    throw new Error('Not yet implemented');
  }

  public withTokenFromResponse(response: AccessTokenResponse): OfferCredentialRequestClientBuilder {
    throw new Error('Not yet implemented');
  }

  public build(): CredentialRequestClient {
    throw new Error('Not yet implemented');
  }
}
