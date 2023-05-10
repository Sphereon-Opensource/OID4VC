import {
  CNonceState,
  CredentialIssuerCallback,
  CredentialOfferState,
  CredentialSupported,
  Display,
  IssuerMetadata,
  IStateManager,
  JWTVerifyCallback,
  TokenErrorResponse,
} from '@sphereon/oid4vci-common'

import { VcIssuer } from '../VcIssuer'
import { MemoryCNonceStateManager, MemoryCredentialOfferStateManager } from '../state-manager'

import { IssuerMetadataBuilderV1_11 } from './IssuerMetadataBuilderV1_11'

export class VcIssuerBuilder {
  issuerMetadataBuilder?: IssuerMetadataBuilderV1_11
  issuerMetadata: Partial<IssuerMetadata> = {}
  userPinRequired?: boolean
  credentialOfferStateManager?: IStateManager<CredentialOfferState>
  cNonceStateManager?: IStateManager<CNonceState>
  issuerCallback?: CredentialIssuerCallback
  verifyCallback?: JWTVerifyCallback

  public withIssuerMetadata(issuerMetadata: IssuerMetadata) {
    this.issuerMetadata = issuerMetadata
  }

  public withIssuerMetadataBuilder(builder: IssuerMetadataBuilderV1_11) {
    this.issuerMetadataBuilder = builder
    return this
  }

  public withCredentialIssuer(issuer: string): VcIssuerBuilder {
    this.issuerMetadata.credential_issuer = issuer
    return this
  }

  public withAuthorizationServer(authorizationServer: string): VcIssuerBuilder {
    this.issuerMetadata.authorization_server = authorizationServer
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): VcIssuerBuilder {
    this.issuerMetadata.credential_endpoint = credentialEndpoint
    return this
  }

  public withBatchCredentialEndpoint(batchCredentialEndpoint: string): VcIssuerBuilder {
    this.issuerMetadata.batch_credential_endpoint = batchCredentialEndpoint
    throw Error('Not implemented yet')
    // return this
  }

  public withTokenEndpoint(tokenEndpoint: string): VcIssuerBuilder {
    this.issuerMetadata.token_endpoint = tokenEndpoint
    return this
  }

  public withIssuerDisplay(issuerDisplay: Display[] | Display): VcIssuerBuilder {
    this.issuerMetadata.display = Array.isArray(issuerDisplay) ? issuerDisplay : [issuerDisplay]
    return this
  }

  public addIssuerDisplay(issuerDisplay: Display): VcIssuerBuilder {
    this.issuerMetadata.display = [...(this.issuerMetadata.display ?? []), issuerDisplay]
    return this
  }

  public withCredentialsSupported(credentialSupported: CredentialSupported | CredentialSupported[]): VcIssuerBuilder {
    this.issuerMetadata.credentials_supported = Array.isArray(credentialSupported) ? credentialSupported : [credentialSupported]
    return this
  }

  public addCredentialsSupported(credentialSupported: CredentialSupported): VcIssuerBuilder {
    this.issuerMetadata.credentials_supported = [...(this.issuerMetadata.credentials_supported ?? []), credentialSupported]
    return this
  }

  public withUserPinRequired(userPinRequired: boolean): VcIssuerBuilder {
    this.userPinRequired = userPinRequired
    return this
  }

  public withCredentialOfferStateManager(iCredentialOfferStateManager: IStateManager<CredentialOfferState>): VcIssuerBuilder {
    this.credentialOfferStateManager = iCredentialOfferStateManager
    return this
  }

  public withInMemoryCredentialOfferState(): VcIssuerBuilder {
    this.withCredentialOfferStateManager(new MemoryCredentialOfferStateManager())
    return this
  }

  public withCNonceStateManager(iCNonceStateManager: IStateManager<CNonceState>): VcIssuerBuilder {
    this.cNonceStateManager = iCNonceStateManager
    return this
  }

  public withInMemoryCNonceState(): VcIssuerBuilder {
    this.withCNonceStateManager(new MemoryCNonceStateManager())
    return this
  }

  withIssuerCallback(cb: CredentialIssuerCallback): VcIssuerBuilder {
    this.issuerCallback = cb
    return this
  }

  withJWTVerifyCallback(verifyCallback: JWTVerifyCallback): VcIssuerBuilder {
    this.verifyCallback = verifyCallback
    return this
  }

  public build(): VcIssuer {
    if (!this.credentialOfferStateManager) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    if (!this.cNonceStateManager) {
      throw new Error(TokenErrorResponse.invalid_request)
    }

    const builder = this.issuerMetadataBuilder?.build()
    const metadata: Partial<IssuerMetadata> = { ...this.issuerMetadata, ...builder }
    // Let's make sure these get merged correctly:
    metadata.credentials_supported = [...(this.issuerMetadata.credentials_supported ?? []), ...(builder?.credentials_supported ?? [])]
    metadata.display = [...(this.issuerMetadata.display ?? []), ...(builder?.display ?? [])]
    if (
      !metadata.credential_endpoint ||
      !metadata.credential_issuer ||
      !this.issuerMetadata.credentials_supported ||
      this.issuerMetadata.credentials_supported.length === 0
    ) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    return new VcIssuer(metadata as IssuerMetadata, {
      userPinRequired: this.userPinRequired ?? false,
      callback: this.issuerCallback,
      verifyCallback: this.verifyCallback,
      stateManager: this.credentialOfferStateManager,
      nonceManager: this.cNonceStateManager,
    })
  }
}
