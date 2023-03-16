import { VcIssuer } from './VcIssuer'
import { ICredentialIssuerMetadataParametersV1_11, ICredentialSupportedV1_11, IIssuerDisplay } from './types'

export class VcIssuerBuilder {
  metadata: ICredentialIssuerMetadataParametersV1_11

  public withCredentialIssuer(issuer: string): VcIssuerBuilder {
    this.metadata.credential_endpoint = issuer
    return this
  }
  public withAuthorizationServer(authorizationServer: string): VcIssuerBuilder {
    this.metadata.authorization_server = authorizationServer
    return this
  }

  public withCredentialEndpoint(credentialEndpoint: string): VcIssuerBuilder {
    this.metadata.credential_endpoint = credentialEndpoint
    return this
  }

  public withBatchCredentialEndpoint(batchCredentialEndpoint: string): VcIssuerBuilder {
    this.metadata.batch_credential_endpoint = batchCredentialEndpoint
    return this
  }

  public withIssuerDisplay(issuerDisplay: IIssuerDisplay | IIssuerDisplay[]): VcIssuerBuilder {
    if (!Array.isArray(issuerDisplay)) this.metadata.display = this.metadata.display ? [...this.metadata.display, issuerDisplay] : [issuerDisplay]
    else {
      this.metadata.display = this.metadata.display ? [...this.metadata.display, ...issuerDisplay] : issuerDisplay
    }
    return this
  }

  public withCredentialsSupported(credentialSupported: ICredentialSupportedV1_11 | ICredentialSupportedV1_11[]): VcIssuerBuilder {
    if (!Array.isArray(credentialSupported))
      this.metadata.credentials_supported = this.metadata.credentials_supported
        ? [...this.metadata.credentials_supported, credentialSupported]
        : [credentialSupported]
    else {
      this.metadata.credentials_supported = this.metadata.credentials_supported
        ? [...this.metadata.credentials_supported, ...credentialSupported]
        : credentialSupported
    }
    return this
  }

  public build(): VcIssuer {
    return new VcIssuer(this.metadata)
  }
}
