import { CredentialRequest, CredentialResponse, getKidFromJWT, IssuerMetadata, TokenErrorResponse } from '@sphereon/openid4vci-common'
import { ICredential, IIssuerId, W3CVerifiableCredential } from '@sphereon/ssi-types'

export class VcIssuer {
  _issuerMetadata: IssuerMetadata
  _userPinRequired?: boolean
  constructor(issuerMetadata: IssuerMetadata, userPinRequired?: boolean) {
    this._issuerMetadata = issuerMetadata
    this._userPinRequired = userPinRequired
  }

  public getIssuerMetadata() {
    return this._issuerMetadata
  }

  public async issueCredentialFromIssueRequest(issueCredentialRequest: CredentialRequest): Promise<CredentialResponse> {
    //TODO: do we want additional validations here?
    if (this.isMetadataSupportCredentialRequestFormat(issueCredentialRequest.format)) {
      return await this.issueCredential(issueCredentialRequest)
    }
    throw new Error(TokenErrorResponse.invalid_request)
  }

  private isMetadataSupportCredentialRequestFormat(requestFormat: string | string[]): boolean {
    for (const credentialSupported of this._issuerMetadata.credentials_supported) {
      if (!Array.isArray(requestFormat) && credentialSupported.format === requestFormat) {
        return true
      } else if (Array.isArray(requestFormat)) {
        for (const format of requestFormat as string[]) {
          if (credentialSupported.format === format) {
            return true
          }
        }
      }
    }
    return false
  }

  private async issueCredential(issueCredentialRequest: CredentialRequest): Promise<CredentialResponse> {
    const credential: ICredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      issuanceDate: new Date().toUTCString(),
      issuer: process.env.issuer_did as IIssuerId,
      type: Array.isArray(issueCredentialRequest.type) ? issueCredentialRequest.type : [issueCredentialRequest.type],
      credentialSubject: {
        id: getKidFromJWT(issueCredentialRequest.proof.jwt as string),
        given_name: 'John Doe',
      },
    }
    return {
      //todo: sign the credential here
      credential: credential as W3CVerifiableCredential,
      format: issueCredentialRequest.format as string,
    }
  }
}
