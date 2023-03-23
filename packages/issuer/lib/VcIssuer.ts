import {
  getKidFromJWT,
  ICredentialIssuerMetadataParametersV1_11,
  ICredentialSuccessResponse,
  IIssueCredentialRequest,
  unsupported_credential_format,
} from '@sphereon/openid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'

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

  private async issueCredential(issueCredentialRequest: IIssueCredentialRequest): Promise<ICredentialSuccessResponse> {
    const credential: ICredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      issuanceDate: new Date().toUTCString(),
      issuer: process.env.issuer_did as string,
      type: issueCredentialRequest.types,
      credentialSubject: {
        id: getKidFromJWT(issueCredentialRequest.proof.jwt as string),
        given_name: 'John Doe',
      },
    }
    return {
      //todo: sign the credential here
      credential: credential as W3CVerifiableCredential,
      format: issueCredentialRequest.format,
    }
  }
}
