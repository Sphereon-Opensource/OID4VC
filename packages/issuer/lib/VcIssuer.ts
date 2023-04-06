import { CredentialIssuerCallback, CredentialRequest, CredentialResponse, IssuerMetadata, TokenErrorResponse } from '@sphereon/openid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'

export class VcIssuer {
  _issuerMetadata: IssuerMetadata
  _userPinRequired?: boolean
  _issuerCallback?: CredentialIssuerCallback

  constructor(issuerMetadata: IssuerMetadata, args?: { userPinRequired?: boolean; callback?: CredentialIssuerCallback }) {
    this._issuerMetadata = issuerMetadata
    this._userPinRequired = args && args.userPinRequired ? args.userPinRequired : false
    this._issuerCallback = args && args.callback ? args.callback : undefined
  }

  public getIssuerMetadata() {
    return this._issuerMetadata
  }

  /**
   * issueCredentialFromIssueRequest
   * @param issueCredentialRequest a credential issuance request
   * @param issuerCallback OPTIONAL. if provided will use this callback instead what is configured in the VcIssuer
   */
  public async issueCredentialFromIssueRequest(
    issueCredentialRequest: CredentialRequest,
    issuerCallback?: CredentialIssuerCallback
  ): Promise<CredentialResponse> {
    //TODO: do we want additional validations here?
    if (this.isMetadataSupportCredentialRequestFormat(issueCredentialRequest.format)) {
      return {
        credential: await this.issueCredential({ credentialRequest: issueCredentialRequest }, issuerCallback),
        format: issueCredentialRequest.format,
      }
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
  private async issueCredential(
    opts: { credentialRequest?: CredentialRequest; credential?: ICredential },
    issuerCallback?: CredentialIssuerCallback
  ): Promise<W3CVerifiableCredential> {
    if ((!opts.credential && !opts.credentialRequest) || !this._issuerCallback) {
      throw new Error('Issuer not configured correctly.')
    }
    return issuerCallback ? await issuerCallback(opts) : this._issuerCallback(opts)
  }
}
