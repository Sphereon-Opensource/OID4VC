import {
  AccessTokenResponse,
  CredentialOfferPayload,
  CredentialOfferRequestWithBaseUrl,
  CredentialOfferV1_0_09,
  EndpointMetadata,
  getIssuerFromCredentialOfferPayload,
  OpenID4VCIServerMetadata,
} from '@sphereon/openid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialRequestClient } from './CredentialRequestClient';
import { convertURIToJsonObject } from './functions';

export class CredentialRequestV1_0_09ClientBuilder {
  credentialEndpoint?: string;
  credentialType?: string | string[];
  format?: CredentialFormat | CredentialFormat[];
  token?: string;

  public static fromURI({ uri, metadata }: { uri: string; metadata?: EndpointMetadata }): CredentialRequestV1_0_09ClientBuilder {
    return CredentialRequestV1_0_09ClientBuilder.fromCredentialOfferRequest({
      request: convertURIToJsonObject(uri, {
        arrayTypeProperties: ['credential_type'],
        requiredProperties: ['issuer', 'credential_type'],
      }) as CredentialOfferPayload,
      metadata,
    });
  }

  public static fromCredentialOfferRequest({
    request,
    metadata,
  }: {
    request: CredentialOfferPayload;
    metadata?: EndpointMetadata;
  }): CredentialRequestV1_0_09ClientBuilder {
    const builder = new CredentialRequestV1_0_09ClientBuilder();
    const issuer = getIssuerFromCredentialOfferPayload(request);
    builder.withCredentialEndpoint(
      metadata?.credential_endpoint ? metadata.credential_endpoint : issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`
    );

    //todo: This basically sets all types available during initiation. Probably the user only wants a subset. So do we want to do this?
    //todo: handle this for v11
    builder.withCredentialType((request as CredentialOfferV1_0_09).credential_type);

    return builder;
  }

  public static fromCredentialOffer({
    credentialOffer,
    metadata,
  }: {
    credentialOffer: CredentialOfferRequestWithBaseUrl;
    metadata?: EndpointMetadata;
  }): CredentialRequestV1_0_09ClientBuilder {
    return CredentialRequestV1_0_09ClientBuilder.fromCredentialOfferRequest({
      request: credentialOffer.request,
      metadata,
    });
  }

  public withCredentialEndpointFromMetadata(metadata: OpenID4VCIServerMetadata): CredentialRequestV1_0_09ClientBuilder {
    this.credentialEndpoint = metadata.credential_endpoint;
    return this;
  }

  public withCredentialEndpoint(credentialEndpoint: string): CredentialRequestV1_0_09ClientBuilder {
    this.credentialEndpoint = credentialEndpoint;
    return this;
  }

  public withCredentialType(credentialType: string | string[]): CredentialRequestV1_0_09ClientBuilder {
    this.credentialType = credentialType;
    return this;
  }

  public withFormat(format: CredentialFormat | CredentialFormat[]): CredentialRequestV1_0_09ClientBuilder {
    this.format = format;
    return this;
  }

  public withToken(accessToken: string): CredentialRequestV1_0_09ClientBuilder {
    this.token = accessToken;
    return this;
  }

  public withTokenFromResponse(response: AccessTokenResponse): CredentialRequestV1_0_09ClientBuilder {
    this.token = response.access_token;
    return this;
  }

  public build(): CredentialRequestClient {
    return new CredentialRequestClient(this);
  }
}
