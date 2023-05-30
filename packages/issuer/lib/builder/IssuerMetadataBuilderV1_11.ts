import { CredentialIssuerMetadata, CredentialSupported, MetadataDisplay } from '@sphereon/oid4vci-common'

import { CredentialSupportedBuilderV1_11 } from './CredentialSupportedBuilderV1_11'
import { DisplayBuilder } from './DisplayBuilder'

export class IssuerMetadataBuilderV1_11 {
  credentialEndpoint: string | undefined
  credentialIssuer: string | undefined
  supportedBuilders: CredentialSupportedBuilderV1_11[] = []
  supportedCredentials: CredentialSupported[] = []
  displayBuilders: DisplayBuilder[] = []
  display: MetadataDisplay[] = []
  batchCredentialEndpoint?: string
  authorizationServer?: string
  tokenEndpoint?: string

  public withBatchCredentialEndpoint(batchCredentialEndpoint: string) {
    this.batchCredentialEndpoint = batchCredentialEndpoint
    throw Error(`Not supported yet`)
  }

  public withAuthorizationServer(authorizationServer: string) {
    this.authorizationServer = authorizationServer
    return this
  }

  public withTokenEndpoint(tokenEndpoint: string) {
    this.tokenEndpoint = tokenEndpoint
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): IssuerMetadataBuilderV1_11 {
    this.credentialEndpoint = credentialEndpoint
    return this
  }

  public withCredentialIssuer(credentialIssuer: string): IssuerMetadataBuilderV1_11 {
    this.credentialIssuer = credentialIssuer
    return this
  }

  public newSupportedCredentialBuilder(): CredentialSupportedBuilderV1_11 {
    const builder = new CredentialSupportedBuilderV1_11()
    this.addSupportedCredentialBuilder(builder)
    return builder
  }

  public addSupportedCredentialBuilder(supportedCredentialBuilder: CredentialSupportedBuilderV1_11) {
    this.supportedBuilders.push(supportedCredentialBuilder)
    return this
  }

  public addSupportedCredential(supportedCredential: CredentialSupported) {
    this.supportedCredentials.push(supportedCredential)
    return this
  }

  public withIssuerDisplay(issuerDisplay: MetadataDisplay[] | MetadataDisplay): IssuerMetadataBuilderV1_11 {
    this.display = Array.isArray(issuerDisplay) ? issuerDisplay : [issuerDisplay]
    return this
  }

  public addDisplay(display: MetadataDisplay) {
    this.display.push(display)
  }

  public addDisplayBuilder(displayBuilder: DisplayBuilder) {
    this.displayBuilders.push(displayBuilder)
  }

  public newDisplayBuilder(): DisplayBuilder {
    const builder = new DisplayBuilder()
    this.addDisplayBuilder(builder)
    return builder
  }

  public build(): CredentialIssuerMetadata {
    if (!this.credentialIssuer) {
      throw Error('No credential issuer supplied')
    } else if (!this.credentialEndpoint) {
      throw Error('No credential endpoint supplied')
    }
    const supportedCredentials: CredentialSupported[] = []
    supportedCredentials.push(...this.supportedCredentials)
    supportedCredentials.push(...this.supportedBuilders.map((builder) => builder.build()))
    if (supportedCredentials.length === 0) {
      throw Error('No supported credentials supplied')
    }

    const display: MetadataDisplay[] = []
    display.push(...this.display)
    display.push(...this.displayBuilders.map((builder) => builder.build()))

    return {
      credential_issuer: this.credentialIssuer,
      credential_endpoint: this.credentialEndpoint,
      credentials_supported: supportedCredentials,
      // batch_credential_endpoint: this.batchCredentialEndpoint; // not implemented yet
      ...(this.authorizationServer && { authorization_server: this.authorizationServer }),
      ...(this.tokenEndpoint && { token_endpoint: this.tokenEndpoint }),
      ...(display.length > 0 && { display }),
    }
  }
}
