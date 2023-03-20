import { unsupported_credential_format } from '@sphereon/openid4vci-common'

import { CredentialFormat, ICredentialIssuerMetadataParametersV1_11, ICredentialSuccessResponse, IIssueCredentialRequest } from './types'

export class VcIssuer {
  _issuerMetadata: ICredentialIssuerMetadataParametersV1_11
  _preAuthorizedCode?: string
  _userPinRequired?: boolean
  constructor(issuerMetadata: ICredentialIssuerMetadataParametersV1_11, preAuthorizedCode?: string, userPinRequired?: boolean) {
    this._issuerMetadata = issuerMetadata
    this._preAuthorizedCode = preAuthorizedCode
    this._userPinRequired = userPinRequired
  }

  public getIssuerMetadata() {
    return this._issuerMetadata
  }

  public async createCredentialOfferDeeplink(): Promise<string> {
    // return 'openid-initiate-issuance://?issuer=https%3A%2F%2Fissuer.research.identiproof.io&credential_type=OpenBadgeCredentialUrl&pre-authorized_code=4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp&user_pin_required=true';
    return `openid-initiate-issuance://?issuer=${this._issuerMetadata.credential_issuer}&credential_type=${this._issuerMetadata.credentials_supported[0].id}&re-authorized_code=${this._preAuthorizedCode}&user_pin_required=${this._userPinRequired}`
  }

  public async issueCredentialFromIssueRequest(issueCredentialRequest: IIssueCredentialRequest): Promise<ICredentialSuccessResponse> {
    //TODO: do we want additional validations here?
    if (this.isMetadataSupportCredentialRequestFormat(issueCredentialRequest.format)) {
      return await this.issueCredential(issueCredentialRequest)
    }
    throw new Error(unsupported_credential_format)
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
