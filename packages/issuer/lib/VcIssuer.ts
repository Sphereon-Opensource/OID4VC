import {
  encodeJsonAsURI,
  ICredentialIssuerMetadataParametersV1_11,
  ICredentialSuccessResponse,
  IIssueCredentialRequest,
  unsupported_credential_format,
} from '@sphereon/openid4vci-common'

import { v4 as uuidv4 } from 'uuid'

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

  public createCredentialOfferDeeplink(): string {
    // openid-credential-offer://credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com
    // %22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCr
    // edential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...
    // FYUaBy%22%7D
    const types: string[] = []
    this._issuerMetadata.credentials_supported.map(cs=> {
      if(cs.types) types.push(...cs.types)
    })
    return `openid-credential-offer://?credential_offer=${encodeJsonAsURI({
      credential_issuer: this._issuerMetadata.credential_issuer,
      credentials: { 
        format: this._issuerMetadata.credentials_supported.map(cs=>cs.format),
        types: types,
        //fixme: @nklomp I've placed this here for now, but later we need to have the concept of sessions and in there we have to keep track of the id 
        issuer_state: uuidv4()
      },
      grants: {
        authorization_code: this._preAuthorizedCode
      }
    })}`
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
