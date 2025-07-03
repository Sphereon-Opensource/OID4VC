import {
  AccessTokenResponse,
  CredentialIssuerMetadataV1_0_15,
  CredentialOfferPayloadV1_0_15,
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromOffer,
  EndpointMetadata,
  ExperimentalSubjectIssuance,
  getIssuerFromCredentialOfferPayload,
  OpenId4VCIVersion,
  UniformCredentialOfferRequest
} from '@sphereon/oid4vci-common'

import { CredentialOfferClient } from './CredentialOfferClient'
import { CredentialRequestClient } from './CredentialRequestClient'

export class CredentialRequestClientBuilderV1_0_15 {
  credentialEndpoint?: string
  deferredCredentialEndpoint?: string
  nonceEndpoint?: string // New in v15
  deferredCredentialAwait = false
  deferredCredentialIntervalInMS = 5000
  credentialIdentifier?: string // Used when authorization_details with credential_identifiers was used
  credentialConfigurationId?: string // Used when scope was used and no credential_identifiers returned
  credentialTypes?: string[] = [] // Legacy support for credential types
  token?: string
  version?: OpenId4VCIVersion
  subjectIssuance?: ExperimentalSubjectIssuance
  issuerState?: string

  // Note: format removed from v15 - credential requests no longer include format parameter

  public static fromCredentialIssuer({
                                       credentialIssuer,
                                       metadata,
                                       version,
                                       credentialIdentifier,
                                       credentialConfigurationId,
                                       credentialTypes
                                     }: {
    credentialIssuer: string
    metadata?: EndpointMetadata
    version?: OpenId4VCIVersion
    credentialIdentifier?: string
    credentialConfigurationId?: string
    credentialTypes?: string | string[]
  }): CredentialRequestClientBuilderV1_0_15 {
    const issuer = credentialIssuer
    const builder = new CredentialRequestClientBuilderV1_0_15()
    builder.withVersion(version ?? OpenId4VCIVersion.VER_1_0_15)
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`))
    if (metadata?.deferred_credential_endpoint) {
      builder.withDeferredCredentialEndpoint(metadata.deferred_credential_endpoint)
    }
    // New in v15: Support for nonce endpoint
    if (metadata?.nonce_endpoint) {
      builder.withNonceEndpoint(metadata.nonce_endpoint)
    }
    if (credentialIdentifier) {
      builder.withCredentialIdentifier(credentialIdentifier)
    }
    if (credentialConfigurationId) {
      builder.withCredentialConfigurationId(credentialConfigurationId)
    }
    if (credentialTypes) {
      builder.withCredentialType(credentialTypes)
    }
    return builder
  }

  public static async fromURI({ uri, metadata }: {
    uri: string;
    metadata?: EndpointMetadata
  }): Promise<CredentialRequestClientBuilderV1_0_15> {
    const offer = await CredentialOfferClient.fromURI(uri)
    return CredentialRequestClientBuilderV1_0_15.fromCredentialOfferRequest({
      request: offer, ...offer,
      metadata,
      version: offer.version
    })
  }

  public static fromCredentialOfferRequest(opts: {
    request: UniformCredentialOfferRequest
    scheme?: string
    baseUrl?: string
    version?: OpenId4VCIVersion
    metadata?: EndpointMetadata
  }): CredentialRequestClientBuilderV1_0_15 {
    const { request, metadata } = opts
    const version = opts.version ?? request.version ?? determineSpecVersionFromOffer(request.original_credential_offer)
    if (version < OpenId4VCIVersion.VER_1_0_15) {
      throw new Error('Versions below v1.0.15 (draft 15) are not supported.')
    }
    const builder = new CredentialRequestClientBuilderV1_0_15()
    const issuer = getIssuerFromCredentialOfferPayload(request.credential_offer) ?? (metadata?.issuer as string)
    builder.withVersion(version)
    builder.withCredentialEndpoint(metadata?.credential_endpoint ?? (issuer.endsWith('/') ? `${issuer}credential` : `${issuer}/credential`))
    if (metadata?.deferred_credential_endpoint) {
      builder.withDeferredCredentialEndpoint(metadata.deferred_credential_endpoint)
    }
    // New in v15: Support for nonce endpoint
    if (metadata?.nonce_endpoint) {
      builder.withNonceEndpoint(metadata.nonce_endpoint)
    }
    const ids: string[] = (request.credential_offer as CredentialOfferPayloadV1_0_15).credential_configuration_ids
    // if there's only one in the offer, we pre-select it. if not, you should provide the credentialConfigurationId
    if (ids.length && ids.length === 1) {
      builder.withCredentialConfigurationId(ids[0])
    }

    return builder
  }

  public static fromCredentialOffer({
                                      credentialOffer,
                                      metadata
                                    }: {
    credentialOffer: CredentialOfferRequestWithBaseUrl
    metadata?: EndpointMetadata
  }): CredentialRequestClientBuilderV1_0_15 {
    const builder = CredentialRequestClientBuilderV1_0_15.fromCredentialOfferRequest({
      request: credentialOffer,
      metadata,
      version: credentialOffer.version
    })

    return builder
  }

  public withCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadataV1_0_15): this {
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

  public withDeferredCredentialEndpointFromMetadata(metadata: CredentialIssuerMetadataV1_0_15): this {
    this.deferredCredentialEndpoint = metadata.deferred_credential_endpoint
    return this
  }

  public withDeferredCredentialEndpoint(deferredCredentialEndpoint: string): this {
    this.deferredCredentialEndpoint = deferredCredentialEndpoint
    return this
  }

  // New in v15: Support for nonce endpoint
  public withNonceEndpointFromMetadata(metadata: CredentialIssuerMetadataV1_0_15): this {
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

  // New in v15: Support for credential_identifier (used when authorization_details with credential_identifiers was used)
  public withCredentialIdentifier(credentialIdentifier: string): this {
    this.credentialIdentifier = credentialIdentifier
    return this
  }

  // New in v15: Support for credential_configuration_id (used when scope was used and no credential_identifiers returned)
  public withCredentialConfigurationId(credentialConfigurationId: string): this {
    this.credentialConfigurationId = credentialConfigurationId
    return this
  }

  // Legacy support for credential types (may be used internally to map to configuration IDs)
  public withCredentialType(credentialTypes: string | string[]): this {
    this.credentialTypes = Array.isArray(credentialTypes) ? credentialTypes : [credentialTypes]
    return this
  }

  // Note: withFormat() method removed in v15 - format is no longer part of credential requests

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
      this.withVersion(OpenId4VCIVersion.VER_1_0_15)
    }
    return new CredentialRequestClient(this)
  }
}
