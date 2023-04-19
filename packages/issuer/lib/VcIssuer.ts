import {
  CredentialIssuerCallback,
  CredentialRequest,
  CredentialResponse,
  ICredentialOfferStateManager,
  IssuerMetadata,
  TokenErrorResponse,
} from '@sphereon/openid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'
import {v4} from "uuid";
import * as process from "process";

export class VcIssuer {
  _issuerMetadata: IssuerMetadata
  _userPinRequired?: boolean
  _issuerCallback?: CredentialIssuerCallback
  private readonly _stateManager: ICredentialOfferStateManager
  private readonly _cNonce: string[] = []
  private readonly _cNonceExpiresIn: number = (parseInt(process.env.C_NONCE_EXPIRES_IN as string) * 1000) || 90 * 1000

  constructor(
    issuerMetadata: IssuerMetadata,
    args: { userPinRequired?: boolean; stateManager: ICredentialOfferStateManager; callback?: CredentialIssuerCallback }
  ) {
    this._issuerMetadata = issuerMetadata
    this._stateManager = args.stateManager
    this._userPinRequired = args && args.userPinRequired ? args.userPinRequired : false
    this._issuerCallback = args?.callback
  }

  public get credentialOfferStateManager(): ICredentialOfferStateManager {
    return this._stateManager
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
      const cNonce = v4()
      this._cNonce.push(cNonce)
      setTimeout(() => {
        const index = this._cNonce.indexOf(cNonce)
        if (index !== -1) {
          this._cNonce.splice(index, 1)
        }
      }, this._cNonceExpiresIn)
      return {
        credential: await this.issueCredential({ credentialRequest: issueCredentialRequest }, issuerCallback),
        format: issueCredentialRequest.format,
        c_nonce: cNonce,
        c_nonce_expires_in: this._cNonceExpiresIn
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
