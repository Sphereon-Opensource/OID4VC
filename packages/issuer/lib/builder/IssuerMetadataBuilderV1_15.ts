import {
  BatchCredentialIssuance,
  CredentialConfigurationSupportedV1_0_15,
  IssuerMetadataV1_0_15,
  MetadataDisplay,
  ResponseEncryption
} from '@sphereon/oid4vci-common'

import { CredentialSupportedBuilderV1_15 } from './CredentialSupportedBuilderV1_15'
import { DisplayBuilder } from './DisplayBuilder'

export class IssuerMetadataBuilderV1_15 {
  credentialEndpoint?: string
  nonceEndpoint?: string // New in v15
  credentialIssuer?: string
  supportedBuilders: CredentialSupportedBuilderV1_15[] = []
  credentialConfigurationsSupported: Record<string, CredentialConfigurationSupportedV1_0_15> = {}
  displayBuilders: DisplayBuilder[] = []
  display: MetadataDisplay[] = []
  batchCredentialIssuance?: BatchCredentialIssuance // Changed from batchCredentialEndpoint in v15
  authorizationServers?: string[]
  tokenEndpoint?: string
  authorizationChallengeEndpoint?: string
  credentialResponseEncryption?: ResponseEncryption
  signedMetadata?: string
  credentialIdentifiersSupported?: boolean

  // Removed withBatchCredentialEndpoint - replaced with batch issuance metadata
  public withBatchCredentialIssuance(batchCredentialIssuance: BatchCredentialIssuance) {
    this.batchCredentialIssuance = batchCredentialIssuance
    return this
  }

  public withAuthorizationServers(authorizationServers: string[]) {
    this.authorizationServers = authorizationServers
    return this
  }

  public withAuthorizationServer(authorizationServer: string) {
    if (this.authorizationServers === undefined) {
      this.authorizationServers = []
    }
    this.authorizationServers.push(authorizationServer)
    return this
  }

  public withAuthorizationChallengeEndpoint(authorizationChallengeEndpoint: string) {
    this.authorizationChallengeEndpoint = authorizationChallengeEndpoint
    return this
  }

  public withTokenEndpoint(tokenEndpoint: string) {
    this.tokenEndpoint = tokenEndpoint
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): IssuerMetadataBuilderV1_15 {
    this.credentialEndpoint = credentialEndpoint
    return this
  }

  // New in v15: Nonce endpoint support
  public withNonceEndpoint(nonceEndpoint: string): IssuerMetadataBuilderV1_15 {
    this.nonceEndpoint = nonceEndpoint
    return this
  }

  public withCredentialIssuer(credentialIssuer: string): IssuerMetadataBuilderV1_15 {
    this.credentialIssuer = credentialIssuer
    return this
  }

  // New in v15: Credential response encryption support
  public withCredentialResponseEncryption(credentialResponseEncryption: ResponseEncryption): IssuerMetadataBuilderV1_15 {
    this.credentialResponseEncryption = credentialResponseEncryption
    return this
  }

  // New in v15: Signed metadata support
  public withSignedMetadata(signedMetadata: string): IssuerMetadataBuilderV1_15 {
    this.signedMetadata = signedMetadata
    return this
  }

  // New in v15: Credential identifiers support
  public withCredentialIdentifiersSupported(credentialIdentifiersSupported: boolean): IssuerMetadataBuilderV1_15 {
    this.credentialIdentifiersSupported = credentialIdentifiersSupported
    return this
  }

  public newSupportedCredentialBuilder(): CredentialSupportedBuilderV1_15 {
    const builder = new CredentialSupportedBuilderV1_15()
    this.addSupportedCredentialBuilder(builder)
    return builder
  }

  public addSupportedCredentialBuilder(supportedCredentialBuilder: CredentialSupportedBuilderV1_15) {
    this.supportedBuilders.push(supportedCredentialBuilder)
    return this
  }

  public addCredentialConfigurationsSupported(id: string, supportedCredential: CredentialConfigurationSupportedV1_0_15) {
    this.credentialConfigurationsSupported[id] = supportedCredential
    return this
  }

  public withIssuerDisplay(issuerDisplay: MetadataDisplay[] | MetadataDisplay): IssuerMetadataBuilderV1_15 {
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

  public build(): IssuerMetadataV1_0_15 {
    if (!this.credentialIssuer) {
      throw Error('No credential issuer supplied')
    } else if (!this.credentialEndpoint) {
      throw Error('No credential endpoint supplied')
    }
    const credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0_15> = this.credentialConfigurationsSupported
    const configurationsEntryList: Record<string, CredentialConfigurationSupportedV1_0_15>[] = this.supportedBuilders.map((builder) =>
      builder.build()
    )
    configurationsEntryList.forEach((configRecord) => {
      Object.keys(configRecord).forEach((key) => {
        credential_configurations_supported[key] = configRecord[key]
      })
    })
    if (Object.keys(credential_configurations_supported).length === 0) {
      throw Error('No supported credentials supplied')
    }

    const display: MetadataDisplay[] = []
    display.push(...this.display)
    display.push(...this.displayBuilders.map((builder) => builder.build()))

    const issuerMetadata: IssuerMetadataV1_0_15 = {
      credential_issuer: this.credentialIssuer,
      credential_endpoint: this.credentialEndpoint,
      credential_configurations_supported,
      ...(this.nonceEndpoint && { nonce_endpoint: this.nonceEndpoint }),
      ...(this.batchCredentialIssuance && { batch_credential_issuance: this.batchCredentialIssuance }),
      ...(this.authorizationServers && { authorization_servers: this.authorizationServers }),
      ...(this.tokenEndpoint && { token_endpoint: this.tokenEndpoint }),
      ...(this.authorizationChallengeEndpoint && { authorization_challenge_endpoint: this.authorizationChallengeEndpoint }),
      ...(this.credentialResponseEncryption && { credential_response_encryption: this.credentialResponseEncryption }),
      ...(this.signedMetadata && { signed_metadata: this.signedMetadata }),
      ...(this.credentialIdentifiersSupported !== undefined && { credential_identifiers_supported: this.credentialIdentifiersSupported }),
      ...(display.length > 0 && { display })
    }

    return issuerMetadata
  }
}