import {
  AccessTokenResponse,
  CredentialIssuerMetadata,
  CredentialOfferPayloadV1_0_08,
  CredentialOfferPayloadV1_0_11,
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromOffer,
  EndpointMetadata,
  ExperimentalSubjectIssuance,
  getIssuerFromCredentialOfferPayload,
  getTypesFromOfferV1_0_11,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  UniformCredentialOfferRequest,
} from '@sphereon/oid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';

import { CredentialOfferClientV1_0_11 } from './CredentialOfferClientV1_0_11';
import { CredentialRequestClientV1_0_11 } from './CredentialRequestClientV1_0_11';

export class CredentialRequestClientBuilderV1_0_11 {
  credentialEndpoint?: string;
  deferredCredentialEndpoint?: string;
  deferredCredentialAwait = false;
  deferredCredentialIntervalInMS = 5000;
  credentialTypes: string[] = [];
  format?: CredentialFormat | OID4VCICredentialFormat;
  token?: string;
  version?: OpenId4VCIVersion;
  subjectIssuance?: ExperimentalSubjectIssuance;

  public static fromCredentialIssuer({
    credentialIssuer,
    metadata,
    version,
    credentialTypes,
  }: {
    credentialIssuer: string;
    metadata?: EndpointMetadata;
    version?: OpenId4VCIVersion;
    credentialTypes: string | string[];
  }): CredentialRequestClientBuilderV1_0_11 {
    const issuer = credentialIssuer;
    const builder = new CredentialRequestClientBuilderV1_0_11();
    builder.withVersion(version ?? OpenId4VCIVersion.VER_1_0_11);
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`));
    if (metadata?.deferred_credential_endpoint) {
      builder.withDeferredCredentialEndpoint(metadata.deferred_credential_endpoint);
    }
    builder.withCredentialType(credentialTypes);
    return builder;
  }

  public static async fromURI({ uri, metadata }: { uri: string; metadata?: EndpointMetadata }): Promise<CredentialRequestClientBuilderV1_0_11> {
    const offer = await CredentialOfferClientV1_0_11.fromURI(uri);
    return CredentialRequestClientBuilderV1_0_11.fromCredentialOfferRequest({ request: offer, ...offer, metadata, version: offer.version });
  }

  public static fromCredentialOfferRequest(opts: {
    request: UniformCredentialOfferRequest;
    scheme?: string;
    baseUrl?: string;
    version?: OpenId4VCIVersion;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilderV1_0_11 {
    const { request, metadata } = opts;
    const version = opts.version ?? request.version ?? determineSpecVersionFromOffer(request.original_credential_offer);
    const builder = new CredentialRequestClientBuilderV1_0_11();
    const issuer = getIssuerFromCredentialOfferPayload(request.credential_offer) ?? (metadata?.issuer as string);
    builder.withVersion(version);
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`));
    if (metadata?.deferred_credential_endpoint) {
      builder.withDeferredCredentialEndpoint(metadata.deferred_credential_endpoint);
    }

    if (version <= OpenId4VCIVersion.VER_1_0_08) {
      //todo: This basically sets all types available during initiation. Probably the user only wants a subset. So do we want to do this?
      builder.withCredentialType((request.original_credential_offer as CredentialOfferPayloadV1_0_08).credential_type);
    } else if (version <= OpenId4VCIVersion.VER_1_0_11) {
      // todo: look whether this is correct
      builder.withCredentialType(getTypesFromOfferV1_0_11(request.credential_offer as CredentialOfferPayloadV1_0_11));
    }

    return builder;
  }

  public static fromCredentialOffer({
    credentialOffer,
    metadata,
  }: {
    credentialOffer: CredentialOfferRequestWithBaseUrl;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilderV1_0_11 {
    return CredentialRequestClientBuilderV1_0_11.fromCredentialOfferRequest({
      request: credentialOffer,
      metadata,
      version: credentialOffer.version,
    });
  }

  public withCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadata): this {
    this.credentialEndpoint = metadata.credential_endpoint;
    return this;
  }

  public withCredentialEndpoint(credentialEndpoint: string): this {
    this.credentialEndpoint = credentialEndpoint;
    return this;
  }

  public withDeferredCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadata): this {
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

  public withCredentialType(credentialTypes: string | string[]): this {
    this.credentialTypes = Array.isArray(credentialTypes) ? credentialTypes : [credentialTypes];
    return this;
  }

  public withFormat(format: CredentialFormat | OID4VCICredentialFormat): this {
    this.format = format;
    return this;
  }

  public withSubjectIssuance(subjectIssuance: ExperimentalSubjectIssuance): this {
    this.subjectIssuance = subjectIssuance;
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

  public build(): CredentialRequestClientV1_0_11 {
    if (!this.version) {
      this.withVersion(OpenId4VCIVersion.VER_1_0_11);
    }
    return new CredentialRequestClientV1_0_11(this);
  }
}
