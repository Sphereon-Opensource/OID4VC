import {
  AccessTokenResponse,
  CredentialIssuerMetadata,
  CredentialIssuerMetadataV1_0_15,
  CredentialOfferRequestWithBaseUrl,
  EndpointMetadata,
  EndpointMetadataResultV1_0_15,
  EndpointMetadataResultV1_0,
  ExperimentalSubjectIssuance,
  OpenId4VCIVersion,
  UniformCredentialOfferRequest,
} from '@sphereon/oid4vci-common'

import { CredentialOfferClient } from './CredentialOfferClient'
import { CredentialRequestClientBuilderV1_0_15 } from './CredentialRequestClientBuilderV1_0_15'
import { CredentialRequestClientBuilderV1_0 } from './CredentialRequestClientBuilderV1_0'

type CredentialRequestClientBuilderVersionSpecific = CredentialRequestClientBuilderV1_0_15 | CredentialRequestClientBuilderV1_0

function isV1_0_15(builder: CredentialRequestClientBuilderVersionSpecific): builder is CredentialRequestClientBuilderV1_0_15 {
  return (builder as CredentialRequestClientBuilderV1_0_15).withCredentialIdentifier !== undefined
}

function isV1_0(builder: CredentialRequestClientBuilderVersionSpecific): builder is CredentialRequestClientBuilderV1_0 {
  return (builder as CredentialRequestClientBuilderV1_0).withCredentialIdentifiers !== undefined
}

export class CredentialRequestClientBuilder {
  private _builder: CredentialRequestClientBuilderVersionSpecific

  private constructor(builder: CredentialRequestClientBuilderVersionSpecific) {
    this._builder = builder
  }

  public static fromCredentialIssuer({
    credentialIssuer,
    metadata,
    version,
    credentialIdentifier,
    credentialIdentifiers,
    credentialTypes,
  }: {
    credentialIssuer: string
    metadata?: EndpointMetadata
    version?: OpenId4VCIVersion
    credentialIdentifier?: string
    credentialIdentifiers?: string[]
    credentialTypes?: string | string[]
  }): CredentialRequestClientBuilder {
    const specVersion = version ?? OpenId4VCIVersion.VER_1_0
    let builder: CredentialRequestClientBuilderVersionSpecific
    if (specVersion >= OpenId4VCIVersion.VER_1_0) {
      builder = CredentialRequestClientBuilderV1_0.fromCredentialIssuer({
        credentialIssuer,
        metadata: metadata as EndpointMetadataResultV1_0,
        version: specVersion,
        credentialIdentifiers: credentialIdentifiers ?? (credentialIdentifier ? [credentialIdentifier] : undefined),
        credentialTypes,
      })
    } else {
      builder = CredentialRequestClientBuilderV1_0_15.fromCredentialIssuer({
        credentialIssuer,
        metadata: metadata as EndpointMetadataResultV1_0_15,
        version: specVersion,
        credentialIdentifier,
        credentialTypes,
      })
    }

    return new CredentialRequestClientBuilder(builder)
  }

  public static async fromURI({
    uri,
    metadata,
  }: {
    uri: string
    metadata?: EndpointMetadataResultV1_0_15
  }): Promise<CredentialRequestClientBuilder> {
    const offer = await CredentialOfferClient.fromURI(uri)
    return CredentialRequestClientBuilder.fromCredentialOfferRequest({
      request: offer,
      ...offer,
      metadata,
      version: offer.version,
    })
  }

  public static fromCredentialOfferRequest(opts: {
    request: UniformCredentialOfferRequest
    scheme?: string
    baseUrl?: string
    version?: OpenId4VCIVersion
    metadata?: EndpointMetadataResultV1_0_15
  }): CredentialRequestClientBuilder {
    //const { request } = opts
    //const version = opts.version ?? request.version ?? determineSpecVersionFromOffer(request.original_credential_offer)
    const builder = CredentialRequestClientBuilderV1_0_15.fromCredentialOfferRequest(opts)

    return new CredentialRequestClientBuilder(builder)
  }

  public static fromCredentialOffer({
    credentialOffer,
    metadata,
  }: {
    credentialOffer: CredentialOfferRequestWithBaseUrl
    metadata?: EndpointMetadataResultV1_0_15
  }): CredentialRequestClientBuilder {
    //const version = determineSpecVersionFromOffer(credentialOffer.credential_offer)
    const builder = CredentialRequestClientBuilderV1_0_15.fromCredentialOffer({
      credentialOffer,
      metadata,
    })

    return new CredentialRequestClientBuilder(builder)
  }

  public getVersion(): OpenId4VCIVersion | undefined {
    return this._builder.version
  }

  public withCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadata | CredentialIssuerMetadataV1_0_15): this {
    if (isV1_0_15(this._builder)) {
      this._builder.withCredentialEndpointFromMetadata(metadata as CredentialIssuerMetadataV1_0_15)
    }
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): this {
    this._builder.withCredentialEndpoint(credentialEndpoint)
    return this
  }

  public withDeferredCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadataV1_0_15): this {
    if (isV1_0_15(this._builder)) {
      this._builder.withDeferredCredentialEndpointFromMetadata(metadata as CredentialIssuerMetadataV1_0_15)
    }
    return this
  }

  public withDeferredCredentialEndpoint(deferredCredentialEndpoint: string): this {
    this._builder.withDeferredCredentialEndpoint(deferredCredentialEndpoint)
    return this
  }

  public withDeferredCredentialAwait(deferredCredentialAwait: boolean, deferredCredentialIntervalInMS?: number): this {
    this._builder.withDeferredCredentialAwait(deferredCredentialAwait, deferredCredentialIntervalInMS)
    return this
  }

  public withCredentialIdentifier(credentialIdentifier: string): this {
    if (this._builder.version === undefined || this._builder.version < OpenId4VCIVersion.VER_1_0_15) {
      throw new Error('Version of spec should be equal or higher than v1_0_15')
    }
    if (isV1_0(this._builder)) {
      this._builder.withCredentialIdentifiers([credentialIdentifier])
    } else if (isV1_0_15(this._builder)) {
      this._builder.withCredentialIdentifier(credentialIdentifier)
    }
    return this
  }

  public withCredentialIdentifiers(credentialIdentifiers: string[]): this {
    if (isV1_0(this._builder)) {
      this._builder.withCredentialIdentifiers(credentialIdentifiers)
    } else if (isV1_0_15(this._builder) && credentialIdentifiers.length > 0) {
      // d15 only supports singular, use the first one
      this._builder.withCredentialIdentifier(credentialIdentifiers[0])
    }
    return this
  }

  public withIssuerState(issuerState?: string): this {
    this._builder.withIssuerState(issuerState)
    return this
  }

  public withCredentialType(credentialTypes: string | string[]): this {
    this._builder.withCredentialType(credentialTypes)
    return this
  }

  public withSubjectIssuance(subjectIssuance: ExperimentalSubjectIssuance): this {
    this._builder.withSubjectIssuance(subjectIssuance)
    return this
  }

  public withToken(accessToken: string): this {
    this._builder.withToken(accessToken)
    return this
  }

  public withTokenFromResponse(response: AccessTokenResponse): this {
    this._builder.withTokenFromResponse(response)
    return this
  }

  public withVersion(version: OpenId4VCIVersion): this {
    this._builder.withVersion(version)
    return this
  }

  public build() {
    return this._builder.build()
  }
}
