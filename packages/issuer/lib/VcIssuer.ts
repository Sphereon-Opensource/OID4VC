import {
  Alg,
  ALG_ERROR,
  AUD_ERROR,
  CredentialIssuerCallback,
  CredentialRequest,
  CredentialResponse,
  IAT_ERROR,
  ICredentialOfferStateManager, ISS_MISSING_IN_NON_PRE_AUTHORIZED_CONTEXT, ISS_MUST_BE_CLIENT_ID,
  ISSUER_CONFIG_ERROR,
  IssuerMetadata,
  Jwt,
  JWT_VERIFY_CONFIG_ERROR,
  JWTVerifyCallback,
  KID_JWK_X5C_ERROR, NO_ISS_IN_PRE_AUTHORIZED_CONTEXT,
  NONCE_ERROR,
  TokenErrorResponse,
  Typ,
  TYP_ERROR,
  UNKNOWN_CLIENT_ERROR,
} from '@sphereon/openid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'

export class VcIssuer {
  _issuerMetadata: IssuerMetadata
  _userPinRequired?: boolean
  _issuerCallback?: CredentialIssuerCallback
  _verifyCallback?: JWTVerifyCallback
  private readonly _stateManager: ICredentialOfferStateManager

  constructor(
    issuerMetadata: IssuerMetadata,
    args: {
      userPinRequired?: boolean
      stateManager: ICredentialOfferStateManager
      callback?: CredentialIssuerCallback
      verifyCallback?: JWTVerifyCallback
    }
  ) {
    this._issuerMetadata = issuerMetadata
    this._stateManager = args.stateManager
    this._userPinRequired = args && args.userPinRequired ? args.userPinRequired : false
    this._issuerCallback = args?.callback
    this._verifyCallback = args?.verifyCallback
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
   * @param preAuthorizedCode the pre-authorized code
   * @param clientId the id from the client making the request
   * @param jwtVerifyCallback OPTIONAL. if provided will use this callback instead what is configured in the VcIssuer
   * @param issuerCallback OPTIONAL. if provided will use this callback instead what is configured in the VcIssuer
   * @param issuerState the state of the issuer
   */
  public async issueCredentialFromIssueRequest(
    issueCredentialRequest: CredentialRequest,
    issuerState: string,
    preAuthorizedCode?: string,
    clientId?: string,
    jwtVerifyCallback?: JWTVerifyCallback,
    issuerCallback?: CredentialIssuerCallback
  ): Promise<CredentialResponse> {
    if (!(await this._stateManager.hasState(issuerState))) {
      throw new Error(UNKNOWN_CLIENT_ERROR)
    }
    await this.validateJWT(issueCredentialRequest, jwtVerifyCallback)
    if (this.isMetadataSupportCredentialRequestFormat(issueCredentialRequest.format)) {
      return {
        credential: await this.issueCredential({ credentialRequest: issueCredentialRequest }, issuerCallback),
        format: issueCredentialRequest.format,
      }
    }
    throw new Error(TokenErrorResponse.invalid_request)
  }

  private async validateJWT(issueCredentialRequest: CredentialRequest, jwtVerifyCallback?: JWTVerifyCallback, clientId?: string, preAuthorizedCode?: string): Promise<void> {
    if ((!Array.isArray(issueCredentialRequest.format) && issueCredentialRequest.format === 'jwt') || issueCredentialRequest.format === 'jwt_vc') {
      issueCredentialRequest.proof.jwt

      if (!this._verifyCallback && !jwtVerifyCallback) {
        throw new Error(JWT_VERIFY_CONFIG_ERROR)
      }

      const { payload, header }: Jwt = jwtVerifyCallback
        ? await jwtVerifyCallback(issueCredentialRequest.proof)
        : await this._verifyCallback!(issueCredentialRequest.proof)

      const { typ, alg, kid, jwk, x5c } = header
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      if (!typ || typ !== Typ['OPENID4VCI-PROOF+JWT']) {
        throw new Error(TYP_ERROR)
      }
      if (!alg || !(alg in Alg)) {
        throw new Error(ALG_ERROR)
      }
      if (!([kid, jwk, x5c].filter((x) => !!x).length === 1)) {
        throw new Error(KID_JWK_X5C_ERROR)
      }

      const { iss, aud, iat, nonce } = payload
      // iss: OPTIONAL (string). The value of this claim MUST be the client_id of the client making the credential request.
      // This claim MUST be omitted if the Access Token authorizing the issuance call was obtained from a Pre-Authorized Code Flow through anonymous access to the Token Endpoint.
      // TODO We need an introspection endpoint in case the AS and RS are separated
      if (!iss && !preAuthorizedCode) {
        throw new Error(ISS_MISSING_IN_NON_PRE_AUTHORIZED_CONTEXT)
      }
      if (iss && preAuthorizedCode) {
        throw new Error(NO_ISS_IN_PRE_AUTHORIZED_CONTEXT)
      }
      if (iss && iss !== clientId) {
        throw new Error(ISS_MUST_BE_CLIENT_ID)
      }
      if (!aud || aud !== this._issuerMetadata.credential_issuer) {
        throw new Error(AUD_ERROR)
      }
      if (!iat) {
        throw new Error(IAT_ERROR)
      }
      if (!nonce) {
        throw new Error(NONCE_ERROR)
      }
    }
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
      throw new Error(ISSUER_CONFIG_ERROR)
    }
    return issuerCallback ? await issuerCallback(opts) : this._issuerCallback(opts)
  }
}
