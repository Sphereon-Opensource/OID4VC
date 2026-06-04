import {
  AuthorizationServerMetadata,
  ClientMetadata,
  ClientResponseType,
  CNonceState,
  CredentialConfigurationSupportedV1_0_15,
  CredentialConfigurationSupportedV1_0,
  CredentialIssuerMetadataOptsV1_0_15,
  CredentialIssuerMetadataOptsV1_0,
  CredentialOfferSession,
  IssuerMetadata,
  IssuerMetadataV1_0_15,
  IssuerMetadataV1_0,
  IStateManager,
  JWTVerifyCallback,
  MetadataDisplay,
  OpenId4VCIVersion,
  TokenErrorResponse,
  TxCode,
  URIState,
} from '@sphereon/oid4vci-common'

import { VcIssuer } from '../VcIssuer'
import { oidcAccessTokenVerifyCallback } from '../functions'
import { MemoryStates } from '../state-manager'
import { CredentialDataSupplier, CredentialSignerCallback } from '../types'

import { IssuerMetadataBuilderV1_15 } from './IssuerMetadataBuilderV1_15'
import { IssuerMetadataBuilderV1_0 } from './IssuerMetadataBuilderV1_0'

export class VcIssuerBuilder {
  issuerMetadataBuilder?: IssuerMetadataBuilderV1_15 | IssuerMetadataBuilderV1_0
  issuerMetadata: Partial<CredentialIssuerMetadataOptsV1_0_15 | CredentialIssuerMetadataOptsV1_0> = {}
  version: OpenId4VCIVersion = OpenId4VCIVersion.VER_1_0
  authorizationServerMetadata: Partial<AuthorizationServerMetadata> = {}
  asClientOpts?: ClientMetadata
  txCode?: TxCode
  defaultCredentialOfferBaseUri?: string
  userPinRequired?: boolean
  cNonceExpiresIn?: number
  credentialOfferStateManager?: IStateManager<CredentialOfferSession>
  credentialOfferURIManager?: IStateManager<URIState>
  cNonceStateManager?: IStateManager<CNonceState>
  credentialSignerCallback?: CredentialSignerCallback
  jwtVerifyCallback?: JWTVerifyCallback
  credentialDataSupplier?: CredentialDataSupplier

  public withVersion(version: OpenId4VCIVersion): this {
    this.version = version
    return this
  }

  public withIssuerMetadata(issuerMetadata: IssuerMetadata) {
    if (!issuerMetadata.credential_configurations_supported) {
      throw new Error('IssuerMetadata should be from type v1_0_15 or higher.')
    }
    this.issuerMetadata = issuerMetadata as IssuerMetadataV1_0_15 | IssuerMetadataV1_0
    return this
  }

  public withASClientMetadata(clientMetadata: ClientMetadata): this {
    this.asClientOpts = clientMetadata
    return this
  }

  public withASClientMetadataParams({
    client_id,
    client_secret,
    redirect_uris,
    response_types,
    ...other
  }: { client_id: string; client_secret?: string; redirect_uris?: string[]; response_types?: ClientResponseType[] } & ClientMetadata): this {
    this.asClientOpts = { ...other, client_id, client_secret, redirect_uris, response_types }
    return this
  }

  public withAuthorizationMetadata(authorizationServerMetadata: AuthorizationServerMetadata) {
    this.authorizationServerMetadata = authorizationServerMetadata
    return this
  }

  public withIssuerMetadataBuilder(builder: IssuerMetadataBuilderV1_15 | IssuerMetadataBuilderV1_0) {
    this.issuerMetadataBuilder = builder
    return this
  }

  public withDefaultCredentialOfferBaseUri(baseUri: string) {
    this.defaultCredentialOfferBaseUri = baseUri
    return this
  }

  public withCredentialIssuer(issuer: string): this {
    this.issuerMetadata.credential_issuer = issuer
    return this
  }

  public withAuthorizationServers(authorizationServers: string | string[]): this {
    this.issuerMetadata.authorization_servers = typeof authorizationServers === 'string' ? [authorizationServers] : authorizationServers
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): this {
    this.issuerMetadata.credential_endpoint = credentialEndpoint
    return this
  }

  public withTokenEndpoint(tokenEndpoint: string): this {
    this.issuerMetadata.token_endpoint = tokenEndpoint
    return this
  }

  public withNonceEndpoint(nonceEndpoint: string): this {
    this.issuerMetadata.nonce_endpoint = nonceEndpoint
    return this
  }

  public withIssuerDisplay(issuerDisplay: MetadataDisplay[] | MetadataDisplay): this {
    this.issuerMetadata.display = Array.isArray(issuerDisplay) ? issuerDisplay : [issuerDisplay]
    return this
  }

  public addIssuerDisplay(issuerDisplay: MetadataDisplay): this {
    this.issuerMetadata.display = [...(this.issuerMetadata.display ?? []), issuerDisplay]
    return this
  }

  public withCredentialConfigurationsSupported(
    credentialConfigurationsSupported: Record<string, CredentialConfigurationSupportedV1_0_15 | CredentialConfigurationSupportedV1_0>,
  ) {
    this.issuerMetadata.credential_configurations_supported = credentialConfigurationsSupported as any
    return this
  }

  public addCredentialConfigurationsSupported(
    id: string,
    supportedCredential: CredentialConfigurationSupportedV1_0_15 | CredentialConfigurationSupportedV1_0,
  ) {
    if (!this.issuerMetadata.credential_configurations_supported) {
      ;(this.issuerMetadata as any).credential_configurations_supported = {}
    }
    ;(this.issuerMetadata as any).credential_configurations_supported[id] = supportedCredential
    return this
  }

  public withTXCode(txCode: TxCode): this {
    this.txCode = txCode
    return this
  }

  public withCredentialOfferURIStateManager(credentialOfferURIManager: IStateManager<URIState>): this {
    this.credentialOfferURIManager = credentialOfferURIManager
    return this
  }

  public withInMemoryCredentialOfferURIState(): this {
    this.withCredentialOfferURIStateManager(new MemoryStates<URIState>())
    return this
  }

  public withCredentialOfferStateManager(credentialOfferManager: IStateManager<CredentialOfferSession>): this {
    this.credentialOfferStateManager = credentialOfferManager
    return this
  }

  public withInMemoryCredentialOfferState(): this {
    this.withCredentialOfferStateManager(new MemoryStates<CredentialOfferSession>())
    return this
  }

  public withCNonceStateManager(cNonceManager: IStateManager<CNonceState>): this {
    this.cNonceStateManager = cNonceManager
    return this
  }

  public withInMemoryCNonceState(): this {
    this.withCNonceStateManager(new MemoryStates())
    return this
  }

  public withCNonceExpiresIn(cNonceExpiresIn: number): this {
    this.cNonceExpiresIn = cNonceExpiresIn
    return this
  }

  public withCredentialSignerCallback(cb: CredentialSignerCallback): this {
    this.credentialSignerCallback = cb
    return this
  }

  public withJWTVerifyCallback(verifyCallback: JWTVerifyCallback): this {
    this.jwtVerifyCallback = verifyCallback
    return this
  }

  public withCredentialDataSupplier(credentialDataSupplier: CredentialDataSupplier): this {
    this.credentialDataSupplier = credentialDataSupplier
    return this
  }

  public build(): VcIssuer {
    if (!this.credentialOfferStateManager) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    if (!this.cNonceStateManager) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    if (Object.keys(this.issuerMetadata).length === 0) {
      throw new Error('issuerMetadata not set')
    }
    if (Object.keys(this.authorizationServerMetadata).length === 0) {
      throw new Error('authorizationServerMetadata not set')
    }

    const builder = this.issuerMetadataBuilder?.build()
    const metadata: Partial<IssuerMetadataV1_0_15> = { ...this.issuerMetadata, ...builder }
    // Let's make sure these get merged correctly:
    metadata.credential_configurations_supported = this.issuerMetadata.credential_configurations_supported
    metadata.display = [...(this.issuerMetadata.display ?? []), ...(builder?.display ?? [])]
    if (!metadata.credential_endpoint || !metadata.credential_issuer || !this.issuerMetadata.credential_configurations_supported) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    if (this.asClientOpts && typeof this.jwtVerifyCallback !== 'function') {
      if (!this.issuerMetadata.credential_issuer) {
        throw Error('issuerMetadata.credential_issuer is required when using asClientOpts')
      } else if (!this.issuerMetadata.authorization_servers) {
        throw Error('issuerMetadata.authorization_servers is required when using asClientOpts')
      }
      this.jwtVerifyCallback = oidcAccessTokenVerifyCallback({
        clientMetadata: this.asClientOpts,
        credentialIssuer: this.issuerMetadata.credential_issuer,
        authorizationServer: this.issuerMetadata.authorization_servers[0],
      })
    }
    return new VcIssuer(
      metadata as CredentialIssuerMetadataOptsV1_0_15 | CredentialIssuerMetadataOptsV1_0,
      this.authorizationServerMetadata as AuthorizationServerMetadata,
      {
        //TODO: discuss this with Niels. I did not find this in the spec. but I think we should somehow communicate this
        ...(this.txCode && { txCode: this.txCode }),
        defaultCredentialOfferBaseUri: this.defaultCredentialOfferBaseUri,
        credentialSignerCallback: this.credentialSignerCallback,
        jwtVerifyCallback: this.jwtVerifyCallback,
        credentialDataSupplier: this.credentialDataSupplier,
        credentialOfferSessions: this.credentialOfferStateManager,
        cNonces: this.cNonceStateManager,
        cNonceExpiresIn: this.cNonceExpiresIn,
        uris: this.credentialOfferURIManager,
        asClientOpts: this.asClientOpts,
        version: this.version,
      },
    )
  }
}
