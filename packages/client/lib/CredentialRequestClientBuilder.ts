import {
  AccessTokenResponse,
  CredentialIssuerMetadata,
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromOffer,
  EndpointMetadata,
  getIssuerFromCredentialOfferPayload,
  OpenId4VCIVersion,
  UniformCredentialOfferRequest,
} from '@sphereon/oid4vci-common';

import { CredentialOfferClient } from './CredentialOfferClient';
import { CredentialRequestClient } from './CredentialRequestClient';

export class CredentialRequestClientBuilder {
  credentialEndpoint?: string;
  token?: string;
  version?: OpenId4VCIVersion;

  public static async fromURI({ uri, metadata }: { uri: string; metadata?: EndpointMetadata }): Promise<CredentialRequestClientBuilder> {
    const offer = await CredentialOfferClient.fromURI(uri);
    return CredentialRequestClientBuilder.fromCredentialOfferRequest({ request: offer, ...offer, metadata, version: offer.version });
  }

  public static fromCredentialOfferRequest(opts: {
    request: UniformCredentialOfferRequest;
    scheme?: string;
    baseUrl?: string;
    version?: OpenId4VCIVersion;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilder {
    const { request, metadata } = opts;
    const version = opts.version ?? request.version ?? determineSpecVersionFromOffer(request.original_credential_offer);
    const builder = new CredentialRequestClientBuilder();
    const issuer = getIssuerFromCredentialOfferPayload(request.credential_offer) ?? (metadata?.issuer as string);
    builder.withVersion(version);
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`));

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
      request: credentialOffer,
      metadata,
      version: credentialOffer.version,
    });
  }

  public withCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadata): CredentialRequestClientBuilder {
    this.credentialEndpoint = metadata.credential_endpoint;
    return this;
  }

  public withCredentialEndpoint(credentialEndpoint: string): CredentialRequestClientBuilder {
    this.credentialEndpoint = credentialEndpoint;
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

  public withVersion(version: OpenId4VCIVersion): CredentialRequestClientBuilder {
    this.version = version;
    return this;
  }

  public build(): CredentialRequestClient {
    if (!this.version) {
      this.withVersion(OpenId4VCIVersion.VER_1_0_11);
    }
    return new CredentialRequestClient(this);
  }
}
