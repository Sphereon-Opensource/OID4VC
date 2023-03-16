import { ICredentialIssuerMetadataParametersV1_11, IIssueCredentialRequest } from './types'

export class VcIssuer {
  _issuerMetadata: ICredentialIssuerMetadataParametersV1_11

  constructor(issuerMetadata: ICredentialIssuerMetadataParametersV1_11) {
    this._issuerMetadata = issuerMetadata
  }

  public getIssuerMetadata() {
    return this._issuerMetadata
  }

  public issueCredential(issueCredentialRequest: IIssueCredentialRequest) {
    //TODO: validation of the credential issue request with metadata
    //TODO: call the generate vc method
  }
}
