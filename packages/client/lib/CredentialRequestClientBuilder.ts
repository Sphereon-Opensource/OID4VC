import {
  AccessTokenResponse,
  CredentialIssuerMetadata,
  CredentialOfferPayloadV1_0_08,
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromOffer,
  EndpointMetadata,
  getIssuerFromCredentialOfferPayload,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  UniformCredentialOfferRequest,
} from '@sphereon/oid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialOfferClient } from './CredentialOfferClient';
import { CredentialRequestClient } from './CredentialRequestClient';

export class CredentialRequestClientBuilder {
  credentialEndpoint?: string;
  credentialTypes: string[] = [];
  format?: CredentialFormat | OID4VCICredentialFormat;
  token?: string;
  version?: OpenId4VCIVersion;

  public static async fromURI({ uri, metadata }: { uri: string; metadata?: EndpointMetadata }): Promise<CredentialRequestClientBuilder> {
    const offer = await CredentialOfferClient.fromURI(uri);
    return CredentialRequestClientBuilder.fromCredentialOfferRequest({ request: offer, ...offer, metadata });
  }

  public static fromCredentialOfferRequest(opts: {
    request: UniformCredentialOfferRequest;
    scheme?: string;
    baseUrl?: string;
    version?: OpenId4VCIVersion;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilder {
    const { request, metadata } = opts;
    const version = opts.version ?? determineSpecVersionFromOffer(request);
    const builder = new CredentialRequestClientBuilder();
    const issuer = getIssuerFromCredentialOfferPayload(request.credential_offer) ?? (metadata?.issuer as string);
    builder.withVersion(version);
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`));

    if (version <= OpenId4VCIVersion.VER_1_0_08) {
      //todo: This basically sets all types available during initiation. Probably the user only wants a subset. So do we want to do this?
      builder.withCredentialType((request.original_credential_offer as CredentialOfferPayloadV1_0_08).credential_type);
    } else {
      // todo: look whether this is correct
      builder.withCredentialType(request.credential_offer.credentials.flatMap((c) => (typeof c === 'string' ? c : c.types)));
    }

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

  public withCredentialType(credentialTypes: string | string[]): CredentialRequestClientBuilder {
    this.credentialTypes = Array.isArray(credentialTypes) ? credentialTypes : [credentialTypes];
    return this;
  }

  public withFormat(format: CredentialFormat | OID4VCICredentialFormat): CredentialRequestClientBuilder {
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
