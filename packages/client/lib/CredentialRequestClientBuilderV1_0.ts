import {
  AccessTokenResponse,
  CredentialIssuerMetadataV1_0,
  CredentialOfferPayloadV1_0,
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromOffer,
  EndpointMetadataResultV1_0,
  ExperimentalSubjectIssuance,
  getIssuerFromCredentialOfferPayload,
  OpenId4VCIVersion,
  UniformCredentialOfferRequest,
} from '@sphereon/oid4vci-common'

import { CredentialOfferClient } from './CredentialOfferClient'
import { CredentialRequestClient } from './CredentialRequestClient'

export class CredentialRequestClientBuilderV1_0 {
  credentialEndpoint?: string
  deferredCredentialEndpoint?: string
  nonceEndpoint?: string
  deferredCredentialAwait = false
  deferredCredentialIntervalInMS = 5000
  credentialIdentifiers?: string[] // 1.0 final: OPTIONAL array (replaces singular credential_identifier)
  credentialConfigurationId?: string // 1.0 final: REQUIRED
  credentialTypes?: string[] = []
  token?: string
  version?: OpenId4VCIVersion
  subjectIssuance?: ExperimentalSubjectIssuance
  issuerState?: string

  public static fromCredentialIssuer({
    credentialIssuer,
    metadata,
    version,
    credentialIdentifiers,
    credentialConfigurationId,
    credentialTypes,
  }: {
    credentialIssuer: string
    metadata?: EndpointMetadataResultV1_0
    version?: OpenId4VCIVersion
    credentialIdentifiers?: string[]
    credentialConfigurationId?: string
    credentialTypes?: string | string[]
  }): CredentialRequestClientBuilderV1_0 {
    const issuer = credentialIssuer
    const builder = new CredentialRequestClientBuilderV1_0()
    builder.withVersion(version ?? OpenId4VCIVersion.VER_1_0)
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`))
    if (metadata?.deferred_credential_endpoint) {
      builder.withDeferredCredentialEndpoint(metadata.deferred_credential_endpoint)
    }
    if (metadata?.credentialIssuerMetadata?.nonce_endpoint) {
      builder.withNonceEndpoint(metadata.credentialIssuerMetadata?.nonce_endpoint)
    }
    if (credentialIdentifiers) {
      builder.withCredentialIdentifiers(credentialIdentifiers)
    }
    if (credentialConfigurationId) {
      builder.withCredentialConfigurationId(credentialConfigurationId)
    }
    if (credentialTypes) {
      builder.withCredentialType(credentialTypes)
    }
    return builder
  }

  public static async fromURI({
    uri,
    metadata,
  }: {
    uri: string
    metadata?: EndpointMetadataResultV1_0
  }): Promise<CredentialRequestClientBuilderV1_0> {
    const offer = await CredentialOfferClient.fromURI(uri)
    return CredentialRequestClientBuilderV1_0.fromCredentialOfferRequest({
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
    metadata?: EndpointMetadataResultV1_0
  }): CredentialRequestClientBuilderV1_0 {
    const { request, metadata } = opts
    const version = opts.version ?? request.version ?? determineSpecVersionFromOffer(request.original_credential_offer)
    const builder = new CredentialRequestClientBuilderV1_0()
    const issuer = getIssuerFromCredentialOfferPayload(request.credential_offer) ?? (metadata ? (metadata.issuer as string) : undefined)
    if (!issuer && !metadata?.credential_endpoint) {
      throw Error(`Issuer could not be determined`)
    }
    builder.withVersion(version >= OpenId4VCIVersion.VER_1_0 ? version : OpenId4VCIVersion.VER_1_0)
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer!.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`))
    if (metadata?.deferred_credential_endpoint) {
      builder.withDeferredCredentialEndpoint(metadata.deferred_credential_endpoint)
    }
    if (metadata?.credentialIssuerMetadata?.nonce_endpoint) {
      builder.withNonceEndpoint(metadata.credentialIssuerMetadata.nonce_endpoint)
    }
    const ids: string[] = (request.credential_offer as CredentialOfferPayloadV1_0).credential_configuration_ids
    if (ids.length && ids.length === 1) {
      builder.withCredentialConfigurationId(ids[0])
    }

    return builder
  }

  public static fromCredentialOffer({
    credentialOffer,
    metadata,
  }: {
    credentialOffer: CredentialOfferRequestWithBaseUrl
    metadata?: EndpointMetadataResultV1_0
  }): CredentialRequestClientBuilderV1_0 {
    return CredentialRequestClientBuilderV1_0.fromCredentialOfferRequest({
      request: credentialOffer,
      metadata,
      version: credentialOffer.version,
    })
  }

  public withCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadataV1_0): this {
    this.credentialEndpoint = metadata.credential_endpoint
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): this {
    this.credentialEndpoint = credentialEndpoint
    return this
  }

  public withIssuerState(issuerState?: string): this {
    this.issuerState = issuerState
    return this
  }

  public withDeferredCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadataV1_0): this {
    this.deferredCredentialEndpoint = metadata.deferred_credential_endpoint
    return this
  }

  public withDeferredCredentialEndpoint(deferredCredentialEndpoint: string): this {
    this.deferredCredentialEndpoint = deferredCredentialEndpoint
    return this
  }

  public withNonceEndpointFromMetadata(metadata: CredentialIssuerMetadataV1_0): this {
    this.nonceEndpoint = metadata.nonce_endpoint
    return this
  }

  public withNonceEndpoint(nonceEndpoint: string): this {
    this.nonceEndpoint = nonceEndpoint
    return this
  }

  public withDeferredCredentialAwait(deferredCredentialAwait: boolean, deferredCredentialIntervalInMS?: number): this {
    this.deferredCredentialAwait = deferredCredentialAwait
    this.deferredCredentialIntervalInMS = deferredCredentialIntervalInMS ?? 5000
    return this
  }

  // 1.0 final: credential_identifiers is an OPTIONAL array
  public withCredentialIdentifiers(credentialIdentifiers: string[]): this {
    this.credentialIdentifiers = credentialIdentifiers
    return this
  }

  // 1.0 final: credential_configuration_id is REQUIRED
  public withCredentialConfigurationId(credentialConfigurationId: string): this {
    this.credentialConfigurationId = credentialConfigurationId
    return this
  }

  public withCredentialType(credentialTypes: string | string[]): this {
    this.credentialTypes = Array.isArray(credentialTypes) ? credentialTypes : [credentialTypes]
    return this
  }

  public withSubjectIssuance(subjectIssuance: ExperimentalSubjectIssuance): this {
    this.subjectIssuance = subjectIssuance
    return this
  }

  public withToken(accessToken: string): this {
    this.token = accessToken
    return this
  }

  public withTokenFromResponse(response: AccessTokenResponse): this {
    this.token = response.access_token
    return this
  }

  public withVersion(version: OpenId4VCIVersion): this {
    this.version = version
    return this
  }

  public build(): CredentialRequestClient {
    if (!this.version) {
      this.withVersion(OpenId4VCIVersion.VER_1_0)
    }
    return new CredentialRequestClient(this)
  }
}
