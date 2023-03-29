import {
  AccessTokenResponse,
  CredentialOfferRequestPayloadV11,
  CredentialOfferRequestWithBaseUrl,
  EndpointMetadata,
  IssuanceInitiationRequestPayloadV9,
  OpenID4VCIServerMetadata,
} from '@sphereon/openid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialRequestClient } from './CredentialRequestClient';
import { convertURIToJsonObject } from './functions';

export class CredentialRequestClientBuilder {
  credentialEndpoint?: string;
  credentialType?: string | string[];
  format?: CredentialFormat | CredentialFormat[];
  token?: string;

  public static fromURI({ uri, metadata }: { uri: string; metadata?: EndpointMetadata }): CredentialRequestClientBuilder {
    return CredentialRequestClientBuilder.fromCredentialOfferRequest({
      request: convertURIToJsonObject(uri, {
        arrayTypeProperties: ['credential_type'],
        requiredProperties: ['issuer', 'credential_type'],
      }) as IssuanceInitiationRequestPayloadV9,
      metadata,
    });
  }

  public static fromCredentialOfferRequest({
    request,
    metadata,
  }: {
    request: IssuanceInitiationRequestPayloadV9 | CredentialOfferRequestPayloadV11;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilder {
    const builder = new CredentialRequestClientBuilder();
    builder.withCredentialEndpoint(
      metadata?.credential_endpoint
        ? metadata.credential_endpoint
        : request.issuer.endsWith('/')
        ? `${request.issuer}credential`
        : `${request.issuer}/credential`
    );

    //todo: This basically sets all types available during initiation. Probably the user only wants a subset. So do we want to do this?
    builder.withCredentialType(request.credential_type);

    return builder;
  }

  public static fromCredentialOffer({
    credentialOffer,
    metadata,
  }: {
    credentialOffer: CredentialOfferRequestWithBaseUrl;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilder {
    return CredentialRequestClientBuilder.fromCredentialOfferRequest({
      request: credentialOffer.request,
      metadata,
    });
  }

  public withCredentialEndpointFromMetadata(metadata: OpenID4VCIServerMetadata): CredentialRequestClientBuilder {
    this.credentialEndpoint = metadata.credential_endpoint;
    return this;
  }

  public withCredentialEndpoint(credentialEndpoint: string): CredentialRequestClientBuilder {
    this.credentialEndpoint = credentialEndpoint;
    return this;
  }

  public withCredentialType(credentialType: string | string[]): CredentialRequestClientBuilder {
    this.credentialType = credentialType;
    return this;
  }

  public withFormat(format: CredentialFormat | CredentialFormat[]): CredentialRequestClientBuilder {
    this.format = format;
    return this;
  }

  public withToken(accessToken: string): CredentialRequestClientBuilder {
    this.token = accessToken;
    return this;
  }

  public withTokenFromResponse(response: AccessTokenResponse): CredentialRequestClientBuilder {
    this.token = response.access_token;
    return this;
  }

  public build(): CredentialRequestClient {
    return new CredentialRequestClient(this);
  }
}
