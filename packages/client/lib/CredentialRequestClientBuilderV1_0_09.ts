import {
  AccessTokenResponse,
  CredentialOfferPayload,
  CredentialOfferPayloadV1_0_09,
  CredentialOfferRequestWithBaseUrl,
  EndpointMetadata,
  getIssuerFromCredentialOfferPayload,
  IssuerMetadata,
} from '@sphereon/oid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialRequestClient } from './CredentialRequestClient';
import { convertURIToJsonObject } from './functions';

export class CredentialRequestClientBuilderV1_0_09 {
  credentialEndpoint?: string;
  credentialType?: string | string[];
  format?: CredentialFormat | CredentialFormat[];
  token?: string;

  public static fromURI({ uri, metadata }: { uri: string; metadata?: EndpointMetadata }): CredentialRequestClientBuilderV1_0_09 {
    return CredentialRequestClientBuilderV1_0_09.fromCredentialOfferRequest({
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
  }): CredentialRequestClientBuilderV1_0_09 {
    const builder = new CredentialRequestClientBuilderV1_0_09();
    const issuer = getIssuerFromCredentialOfferPayload(request)
      ? (getIssuerFromCredentialOfferPayload(request) as string)
      : (metadata?.issuer as string);
    builder.withCredentialEndpoint(
      metadata?.credential_endpoint ? metadata.credential_endpoint : issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`
    );

    //todo: This basically sets all types available during initiation. Probably the user only wants a subset. So do we want to do this?
    //todo: handle this for v11
    builder.withCredentialType((request as CredentialOfferPayloadV1_0_09).credential_type);

    return builder;
  }

  public static fromCredentialOffer({
    credentialOffer,
    metadata,
  }: {
    credentialOffer: CredentialOfferRequestWithBaseUrl;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilderV1_0_09 {
    return CredentialRequestClientBuilderV1_0_09.fromCredentialOfferRequest({
      request: credentialOffer.request,
      metadata,
    });
  }

  public withCredentialEndpointFromMetadata(metadata: IssuerMetadata): CredentialRequestClientBuilderV1_0_09 {
    this.credentialEndpoint = metadata.credential_endpoint;
    return this;
  }

  public withCredentialEndpoint(credentialEndpoint: string): CredentialRequestClientBuilderV1_0_09 {
    this.credentialEndpoint = credentialEndpoint;
    return this;
  }

  public withCredentialType(credentialType: string | string[]): CredentialRequestClientBuilderV1_0_09 {
    this.credentialType = credentialType;
    return this;
  }

  public withFormat(format: CredentialFormat | CredentialFormat[]): CredentialRequestClientBuilderV1_0_09 {
    this.format = format;
    return this;
  }

  public withToken(accessToken: string): CredentialRequestClientBuilderV1_0_09 {
    this.token = accessToken;
    return this;
  }

  public withTokenFromResponse(response: AccessTokenResponse): CredentialRequestClientBuilderV1_0_09 {
    this.token = response.access_token;
    return this;
  }

  public build(): CredentialRequestClient {
    return new CredentialRequestClient(this);
  }
}
