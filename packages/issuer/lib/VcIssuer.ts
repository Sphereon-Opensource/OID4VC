import {
  ICredentialIssuerMetadataParametersV1_11,
  ICredentialSuccessResponse,
  IIssueCredentialRequest,
  unsupported_credential_format,
} from '@sphereon/openid4vci-common'

export class VcIssuer {
  _issuerMetadata: ICredentialIssuerMetadataParametersV1_11
  _userPinRequired?: boolean
  constructor(issuerMetadata: ICredentialIssuerMetadataParametersV1_11, userPinRequired?: boolean) {
    this._issuerMetadata = issuerMetadata
    this._userPinRequired = userPinRequired
  }

  public getIssuerMetadata() {
    return this._issuerMetadata
  }

  public async issueCredentialFromIssueRequest(issueCredentialRequest: IIssueCredentialRequest): Promise<ICredentialSuccessResponse> {
    //TODO: do we want additional validations here?
    if (this.isMetadataSupportCredentialRequestFormat(issueCredentialRequest.format)) {
      return await this.issueCredential(issueCredentialRequest)
    }
    throw new Error(unsupported_credential_format)
  }

  private isMetadataSupportCredentialRequestFormat(requestFormat: string): boolean {
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
