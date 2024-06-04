import {
  AccessTokenResponse,
  CredentialIssuerMetadataV1_0_13,
  CredentialOfferPayloadV1_0_13,
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
  deferredCredentialEndpoint?: string;
  deferredCredentialAwait = false;
  deferredCredentialIntervalInMS = 5000;
  credentialIdentifier?: string;
  credentialTypes?: string[] = [];
  format?: CredentialFormat | OID4VCICredentialFormat;
  token?: string;
  version?: OpenId4VCIVersion;

  public static fromCredentialIssuer({
    credentialIssuer,
    metadata,
    version,
    credentialIdentifier,
    credentialTypes,
  }: {
    credentialIssuer: string;
    metadata?: EndpointMetadata;
    version?: OpenId4VCIVersion;
    credentialIdentifier?: string;
    credentialTypes?: string | string[];
  }): CredentialRequestClientBuilder {
    const issuer = credentialIssuer;
    const builder = new CredentialRequestClientBuilder();
    builder.withVersion(version ?? OpenId4VCIVersion.VER_1_0_11);
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`));
    if (metadata?.deferred_credential_endpoint) {
      builder.withDeferredCredentialEndpoint(metadata.deferred_credential_endpoint);
    }
    if (credentialIdentifier) {
      builder.withCredentialIdentifier(credentialIdentifier);
    }
    if (credentialTypes) {
      builder.withCredentialType(credentialTypes);
    }
    return builder;
  }

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
    if (version < OpenId4VCIVersion.VER_1_0_13) {
      throw new Error('Versions below v1.0.13 (draft 13) are not supported.');
    }
    const builder = new CredentialRequestClientBuilder();
    const issuer = getIssuerFromCredentialOfferPayload(request.credential_offer) ?? (metadata?.issuer as string);
    builder.withVersion(version);
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`));
    if (metadata?.deferred_credential_endpoint) {
      builder.withDeferredCredentialEndpoint(metadata.deferred_credential_endpoint);
    }
    const ids: string[] = (request.credential_offer as CredentialOfferPayloadV1_0_13).credential_configuration_ids;
    // if there's only one in the offer, we pre-select it. if not, you should provide the credentialType
    if (ids.length && ids.length === 1) {
      builder.withCredentialIdentifier(ids[0]);
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
      version: credentialOffer.version,
    });
  }

  public withCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadataV1_0_13): this {
    this.credentialEndpoint = metadata.credential_endpoint;
    return this;
  }

  public withCredentialEndpoint(credentialEndpoint: string): this {
    this.credentialEndpoint = credentialEndpoint;
    return this;
  }

  public withDeferredCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadataV1_0_13): this {
    this.deferredCredentialEndpoint = metadata.deferred_credential_endpoint;
    return this;
  }

  public withDeferredCredentialEndpoint(deferredCredentialEndpoint: string): this {
    this.deferredCredentialEndpoint = deferredCredentialEndpoint;
    return this;
  }

  public withDeferredCredentialAwait(deferredCredentialAwait: boolean, deferredCredentialIntervalInMS?: number): this {
    this.deferredCredentialAwait = deferredCredentialAwait;
    this.deferredCredentialIntervalInMS = deferredCredentialIntervalInMS ?? 5000;
    return this;
  }

  public withCredentialIdentifier(credentialIdentifier: string): this {
    this.credentialIdentifier = credentialIdentifier;
    return this;
  }

  public withCredentialType(credentialTypes: string | string[]): this {
    this.credentialTypes = Array.isArray(credentialTypes) ? credentialTypes : [credentialTypes];
    return this;
  }

  public withFormat(format: CredentialFormat | OID4VCICredentialFormat): this {
    this.format = format;
    return this;
  }

  public withToken(accessToken: string): this {
    this.token = accessToken;
    return this;
  }

  public withTokenFromResponse(response: AccessTokenResponse): this {
    this.token = response.access_token;
    return this;
  }

  public withVersion(version: OpenId4VCIVersion): this {
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
