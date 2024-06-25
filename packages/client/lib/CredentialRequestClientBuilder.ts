import {
  AccessTokenResponse,
  CredentialIssuerMetadata,
  CredentialIssuerMetadataV1_0_13,
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromOffer,
  EndpointMetadata,
  ExperimentalSubjectIssuance,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  UniformCredentialOfferRequest
} from '@sphereon/oid4vci-common'
import { CredentialFormat } from '@sphereon/ssi-types'

import { CredentialOfferClient } from './CredentialOfferClient';
import { CredentialRequestClientBuilderV1_0_11 } from './CredentialRequestClientBuilderV1_0_11';
import { CredentialRequestClientBuilderV1_0_13 } from './CredentialRequestClientBuilderV1_0_13';

type CredentialRequestClientBuilderVersionSpecific = CredentialRequestClientBuilderV1_0_11 | CredentialRequestClientBuilderV1_0_13;

function isV1_0_13(builder: CredentialRequestClientBuilderVersionSpecific): builder is CredentialRequestClientBuilderV1_0_13 {
  return (builder as CredentialRequestClientBuilderV1_0_13).withCredentialIdentifier !== undefined;
}

export class CredentialRequestClientBuilder {
  private _builder: CredentialRequestClientBuilderVersionSpecific;

  private constructor(builder: CredentialRequestClientBuilderVersionSpecific) {
    this._builder = builder;
  }

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
    const specVersion = version ?? OpenId4VCIVersion.VER_1_0_13;
    let builder;

    if (specVersion >= OpenId4VCIVersion.VER_1_0_13) {
      builder = CredentialRequestClientBuilderV1_0_13.fromCredentialIssuer({
        credentialIssuer,
        metadata,
        version,
        credentialIdentifier,
        credentialTypes,
      });
    } else {
      if (!credentialTypes || credentialTypes.length === 0) {
        throw new Error('CredentialTypes must be provided for v1_0_11');
      }
      builder = CredentialRequestClientBuilderV1_0_11.fromCredentialIssuer({
        credentialIssuer,
        metadata,
        version,
        credentialTypes,
      });
    }

    return new CredentialRequestClientBuilder(builder);
  }

  public static async fromURI({ uri, metadata }: { uri: string; metadata?: EndpointMetadata }): Promise<CredentialRequestClientBuilder> {
    const offer = await CredentialOfferClient.fromURI(uri);
    return CredentialRequestClientBuilder.fromCredentialOfferRequest({
      request: offer,
      ...offer,
      metadata,
      version: offer.version,
    });
  }

  public static fromCredentialOfferRequest(opts: {
    request: UniformCredentialOfferRequest;
    scheme?: string;
    baseUrl?: string;
    version?: OpenId4VCIVersion;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilder {
    const { request } = opts;
    const version = opts.version ?? request.version ?? determineSpecVersionFromOffer(request.original_credential_offer);
    let builder;

    if (version < OpenId4VCIVersion.VER_1_0_13) {
      builder = CredentialRequestClientBuilderV1_0_11.fromCredentialOfferRequest(opts);
    } else {
      builder = CredentialRequestClientBuilderV1_0_13.fromCredentialOfferRequest(opts);
    }

    return new CredentialRequestClientBuilder(builder);
  }

  public static fromCredentialOffer({
                                      credentialOffer,
                                      metadata,
                                    }: {
    credentialOffer: CredentialOfferRequestWithBaseUrl;
    metadata?: EndpointMetadata;
  }): CredentialRequestClientBuilder {
    const version = determineSpecVersionFromOffer(credentialOffer.credential_offer);
    let builder;

    if (version < OpenId4VCIVersion.VER_1_0_13) {
      builder = CredentialRequestClientBuilderV1_0_11.fromCredentialOffer({
        credentialOffer,
        metadata,
      });
    } else {
      builder = CredentialRequestClientBuilderV1_0_13.fromCredentialOffer({
        credentialOffer,
        metadata,
      });
    }

    return new CredentialRequestClientBuilder(builder);
  }

  public getVersion(): OpenId4VCIVersion | undefined {
    return this._builder.version;
  }

  public withCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadata | CredentialIssuerMetadataV1_0_13): this {
    if (isV1_0_13(this._builder)) {
      this._builder.withCredentialEndpointFromMetadata(metadata as CredentialIssuerMetadataV1_0_13)
    } else {
      this._builder.withCredentialEndpointFromMetadata(metadata as CredentialIssuerMetadata)
    }
    return this;
  }

  public withCredentialEndpoint(credentialEndpoint: string): this {
    this._builder.withCredentialEndpoint(credentialEndpoint);
    return this;
  }

  public withDeferredCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadata | CredentialIssuerMetadataV1_0_13): this {
    if (isV1_0_13(this._builder)) {
      this._builder.withDeferredCredentialEndpointFromMetadata(metadata as CredentialIssuerMetadataV1_0_13);
    } else {
      this._builder.withDeferredCredentialEndpointFromMetadata(metadata as CredentialIssuerMetadata);
    }
    return this;
  }

  public withDeferredCredentialEndpoint(deferredCredentialEndpoint: string): this {
    this._builder.withDeferredCredentialEndpoint(deferredCredentialEndpoint);
    return this;
  }

  public withDeferredCredentialAwait(deferredCredentialAwait: boolean, deferredCredentialIntervalInMS?: number): this {
    this._builder.withDeferredCredentialAwait(deferredCredentialAwait, deferredCredentialIntervalInMS);
    return this;
  }

  public withCredentialIdentifier(credentialIdentifier: string): this {
    if (this._builder.version === undefined || this._builder.version < OpenId4VCIVersion.VER_1_0_13) {
      throw new Error('Version of spec should be equal or higher than v1_0_13');
    }
    (this._builder as CredentialRequestClientBuilderV1_0_13).withCredentialIdentifier(credentialIdentifier);
    return this;
  }

  public withCredentialType(credentialTypes: string | string[]): this {
    this._builder.withCredentialType(credentialTypes);
    return this;
  }

  public withFormat(format: CredentialFormat | OID4VCICredentialFormat): this {
    this._builder.withFormat(format);
    return this;
  }

  public withSubjectIssuance(subjectIssuance: ExperimentalSubjectIssuance): this {
    this._builder.withSubjectIssuance(subjectIssuance);
    return this;
  }

  public withToken(accessToken: string): this {
    this._builder.withToken(accessToken);
    return this;
  }

  public withTokenFromResponse(response: AccessTokenResponse): this {
    this._builder.withTokenFromResponse(response);
    return this;
  }

  public withVersion(version: OpenId4VCIVersion): this {
    this._builder.withVersion(version);
    return this;
  }

  public build() {
    return this._builder.build();
  }
}
