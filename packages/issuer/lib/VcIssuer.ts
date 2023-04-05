import {
  CredentialIssuerCallback,
  CredentialRequest,
  CredentialResponse,
  getKidFromJWT,
  ICredentialOfferStateManager,
  IssuerMetadata,
  TokenErrorResponse,
} from '@sphereon/openid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'

export class VcIssuer {
  _issuerMetadata: IssuerMetadata
  _userPinRequired?: boolean
  _issuerCallback?: CredentialIssuerCallback
  private readonly _iCredentialOfferStateManager?: ICredentialOfferStateManager
  constructor(issuerMetadata: IssuerMetadata, userPinRequired?: boolean, iCredentialOfferStateManager?: ICredentialOfferStateManager) {
    this._issuerMetadata = issuerMetadata
    this._userPinRequired = userPinRequired
    this._iCredentialOfferStateManager = iCredentialOfferStateManager
  }

  public get credentialOfferStateManager(): ICredentialOfferStateManager | undefined {
    return this._iCredentialOfferStateManager
  }

  public getIssuerMetadata() {
    return this._issuerMetadata
  }

  public async issueCredentialFromIssueRequest(issueCredentialRequest: CredentialRequest): Promise<CredentialResponse> {
    //TODO: do we want additional validations here?
    if (this.isMetadataSupportCredentialRequestFormat(issueCredentialRequest.format)) {
      return {
        credential: await this.issueCredential({ credentialRequest: issueCredentialRequest }),
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
  private async issueCredential(opts: { credentialRequest?: CredentialRequest; credential?: ICredential }): Promise<W3CVerifiableCredential> {
    if ((!opts.credential && !opts.credentialRequest) || !this._issuerCallback) {
      throw new Error('Issuer not configured correctly.')
    }
    return await this._issuerCallback(opts)
  }
}
