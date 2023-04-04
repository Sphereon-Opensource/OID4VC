import {
  CredentialIssuerMetadataSupportedCredentials,
  Display,
  ICredentialOfferStateManager,
  IssuerMetadata,
  TokenErrorResponse,
} from '@sphereon/openid4vci-common'

import { VcIssuer } from '../VcIssuer'

export class VcIssuerBuilder {
  credentialIssuer?: string
  authorizationServer?: string
  credentialEndpoint?: string
  batchCredentialEndpoint?: string
  tokenEndpoint?: string
  issuerDisplay?: Display[]
  credentialsSupported?: CredentialIssuerMetadataSupportedCredentials[]
  userPinRequired?: boolean
  credentialOfferStateManager?: ICredentialOfferStateManager

  public withCredentialIssuer(issuer: string): VcIssuerBuilder {
    this.credentialIssuer = issuer
    return this
  }
  public withAuthorizationServer(authorizationServer: string): VcIssuerBuilder {
    this.authorizationServer = authorizationServer
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): VcIssuerBuilder {
    this.credentialEndpoint = credentialEndpoint
    return this
  }

  public withBatchCredentialEndpoint(batchCredentialEndpoint: string): VcIssuerBuilder {
    this.batchCredentialEndpoint = batchCredentialEndpoint
    return this
  }

  public withTokenEndpoint(tokenEndpoint: string): VcIssuerBuilder {
    this.tokenEndpoint = tokenEndpoint
    return this
  }

  public withIssuerDisplay(issuerDisplay: Display[] | Display): VcIssuerBuilder {
    this.issuerDisplay = Array.isArray(issuerDisplay) ? issuerDisplay : [issuerDisplay]
    return this
  }

  public addIssuerDisplay(issuerDisplay: Display[] | Display): VcIssuerBuilder {
    if (!Array.isArray(issuerDisplay)) this.issuerDisplay = this.issuerDisplay ? [...this.issuerDisplay, issuerDisplay] : [issuerDisplay]
    else {
      this.issuerDisplay = this.issuerDisplay ? [...this.issuerDisplay, ...issuerDisplay] : issuerDisplay
    }
    return this
  }

  public withCredentialsSupported(
    credentialSupported: CredentialIssuerMetadataSupportedCredentials | CredentialIssuerMetadataSupportedCredentials[]
  ): VcIssuerBuilder {
    this.credentialsSupported = Array.isArray(credentialSupported) ? credentialSupported : [credentialSupported]
    return this
  }

  public addCredentialsSupported(
    credentialSupported: CredentialIssuerMetadataSupportedCredentials | CredentialIssuerMetadataSupportedCredentials[]
  ): VcIssuerBuilder {
    if (!Array.isArray(credentialSupported))
      this.credentialsSupported = this.credentialsSupported ? [...this.credentialsSupported, credentialSupported] : [credentialSupported]
    else {
      this.credentialsSupported = this.credentialsSupported ? [...this.credentialsSupported, ...credentialSupported] : credentialSupported
    }
    return this
  }

  public withUserPinRequired(userPinRequired: boolean): VcIssuerBuilder {
    this.userPinRequired = userPinRequired
    return this
  }

  public withInMemoryCredentialOfferStates(iCredentialOfferStateManager: ICredentialOfferStateManager): VcIssuerBuilder {
    this.credentialOfferStateManager = iCredentialOfferStateManager
    return this
  }

  public build(): VcIssuer {
    if (!this.credentialEndpoint || !this.credentialIssuer || !this.credentialsSupported) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    if (!this.userPinRequired) {
      this.userPinRequired = false
    }
    const metadata: IssuerMetadata = {
      credential_endpoint: this.credentialEndpoint,
      credential_issuer: this.credentialIssuer,
      credentials_supported: this.credentialsSupported,
    }
    if (this.issuerDisplay) {
      metadata.display = this.issuerDisplay
    }
    if (this.batchCredentialEndpoint) {
      metadata.batch_credential_endpoint = this.batchCredentialEndpoint
    }
    if (this.authorizationServer) {
      metadata.authorization_server = this.authorizationServer
    }
    if (this.tokenEndpoint) {
      metadata.token_endpoint = this.tokenEndpoint
    }
    return new VcIssuer(metadata, this.userPinRequired, this.credentialOfferStateManager)
  }
}
