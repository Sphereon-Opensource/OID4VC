import {
  CredentialErrorResponse,
  CredentialFormat,
  ICredentialIssuerMetadataParametersV1_11,
  ICredentialSuccessResponse,
  IIssueCredentialRequest,
} from './types'

export class VcIssuer {
  _issuerMetadata: ICredentialIssuerMetadataParametersV1_11

  constructor(issuerMetadata: ICredentialIssuerMetadataParametersV1_11) {
    this._issuerMetadata = issuerMetadata
  }

  public getIssuerMetadata() {
    return this._issuerMetadata
  }

  public async issueCredentialFromIssueRequest(issueCredentialRequest: IIssueCredentialRequest): Promise<ICredentialSuccessResponse> {
    //TODO: do we want additional validations here?
    if (this.isMetadataSupportCredentialRequestFormat(issueCredentialRequest.format)) {
      return await this.issueCredential(issueCredentialRequest)
    }
    throw new Error(CredentialErrorResponse.unsupported_credential_format.valueOf())
  }

  private isMetadataSupportCredentialRequestFormat(requestFormat: CredentialFormat): boolean {
    for (const credentialSupported of this._issuerMetadata.credentials_supported) {
      if (credentialSupported.format === requestFormat) {
        return true
      }
    }
    return false
  }

  private async issueCredential(_issueCredentialRequest: IIssueCredentialRequest): Promise<ICredentialSuccessResponse> {
    throw new Error('not implemented')
  }
}
