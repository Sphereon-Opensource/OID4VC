import {
  CNonceState,
  CredentialConfigurationSupportedV1_0_13,
  CredentialOfferSession, IssuerMetadata,
  IssuerMetadataV1_0_13,
  IStateManager,
  JWTVerifyCallback,
  MetadataDisplay,
  TokenErrorResponse,
  TxCode,
  URIState
} from '@sphereon/oid4vci-common'
import { CredentialIssuerMetadataOptsV1_0_13 } from '@sphereon/oid4vci-common/dist/types/v1_0_13.types'

import { VcIssuer } from '../VcIssuer'
import { MemoryStates } from '../state-manager'
import { CredentialDataSupplier, CredentialSignerCallback } from '../types'

import { IssuerMetadataBuilderV1_13 } from './IssuerMetadataBuilderV1_13'

export class VcIssuerBuilder<DIDDoc extends object> {
  issuerMetadataBuilder?: IssuerMetadataBuilderV1_13
  issuerMetadata: Partial<CredentialIssuerMetadataOptsV1_0_13> = {}
  txCode?: TxCode
  defaultCredentialOfferBaseUri?: string
  userPinRequired?: boolean
  cNonceExpiresIn?: number
  credentialOfferStateManager?: IStateManager<CredentialOfferSession>
  credentialOfferURIManager?: IStateManager<URIState>
  cNonceStateManager?: IStateManager<CNonceState>
  credentialSignerCallback?: CredentialSignerCallback<DIDDoc>
  jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>
  credentialDataSupplier?: CredentialDataSupplier

  public withIssuerMetadata(issuerMetadata: IssuerMetadata) {
    if (!issuerMetadata.credential_configurations_supported) {
      throw new Error('IssuerMetadata should be from type v1_0_13 or higher.')
    }
    this.issuerMetadata = issuerMetadata as IssuerMetadataV1_0_13
    return this
  }

  public withIssuerMetadataBuilder(builder: IssuerMetadataBuilderV1_13) {
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

  public withBatchCredentialEndpoint(batchCredentialEndpoint: string): this {
    this.issuerMetadata.batch_credential_endpoint = batchCredentialEndpoint
    throw Error('Not implemented yet')
    // return this
  }

  public withTokenEndpoint(tokenEndpoint: string): this {
    this.issuerMetadata.token_endpoint = tokenEndpoint
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

  public withCredentialConfigurationsSupported(credentialConfigurationsSupported: Record<string, CredentialConfigurationSupportedV1_0_13>) {
    this.issuerMetadata.credential_configurations_supported = credentialConfigurationsSupported
    return this
  }

  public addCredentialConfigurationsSupported(id: string, supportedCredential: CredentialConfigurationSupportedV1_0_13) {
    if (!this.issuerMetadata.credential_configurations_supported) {
      this.issuerMetadata.credential_configurations_supported = {}
    }
    this.issuerMetadata.credential_configurations_supported[id] = supportedCredential
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

  public withCredentialSignerCallback(cb: CredentialSignerCallback<DIDDoc>): this {
    this.credentialSignerCallback = cb
    return this
  }

  public withJWTVerifyCallback(verifyCallback: JWTVerifyCallback<DIDDoc>): this {
    this.jwtVerifyCallback = verifyCallback
    return this
  }

  public withCredentialDataSupplier(credentialDataSupplier: CredentialDataSupplier): this {
    this.credentialDataSupplier = credentialDataSupplier
    return this
  }

  public build(): VcIssuer<DIDDoc> {
    if (!this.credentialOfferStateManager) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    if (!this.cNonceStateManager) {
      throw new Error(TokenErrorResponse.invalid_request)
    }

    const builder = this.issuerMetadataBuilder?.build()
    const metadata: Partial<IssuerMetadataV1_0_13> = { ...this.issuerMetadata, ...builder }
    // Let's make sure these get merged correctly:
    metadata.credential_configurations_supported = this.issuerMetadata.credential_configurations_supported
    metadata.display = [...(this.issuerMetadata.display ?? []), ...(builder?.display ?? [])]
    if (!metadata.credential_endpoint || !metadata.credential_issuer || !this.issuerMetadata.credential_configurations_supported) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    return new VcIssuer(metadata as IssuerMetadataV1_0_13, {
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
    })
  }
}
