import * as process from 'process'

import {
  Alg,
  ALG_ERROR,
  AUD_ERROR,
  CNonceState,
  CREDENTIAL_MISSING_ERROR,
  CredentialFormat,
  CredentialIssuerCallback,
  CredentialOfferState,
  CredentialRequest,
  CredentialResponse,
  Grant,
  GRANTS_MUST_NOT_BE_UNDEFINED,
  IAT_ERROR,
  ISS_MUST_BE_CLIENT_ID,
  ISSUER_CONFIG_ERROR,
  IssuerCredentialSubject,
  IssuerMetadata,
  IStateManager,
  Jwt,
  JWT_VERIFY_CONFIG_ERROR,
  JWTVerifyCallback,
  KID_JWK_X5C_ERROR,
  NO_ISS_IN_AUTHORIZATION_CODE_CONTEXT,
  NONCE_ERROR,
  TokenErrorResponse,
  Typ,
  TYP_ERROR,
} from '@sphereon/openid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'
import { v4 } from 'uuid'

export class VcIssuer {
  _issuerMetadata: IssuerMetadata
  _userPinRequired?: boolean
  _issuerCallback?: CredentialIssuerCallback
  _verifyCallback?: JWTVerifyCallback
  private readonly _stateManager: IStateManager<CredentialOfferState>
  private readonly nonceManager: IStateManager<CNonceState>
  // TODO add config option
  private readonly _cNonceExpiresIn: number = parseInt(process.env.C_NONCE_EXPIRES_IN as string) * 1000 || 90 * 1000

  constructor(
    issuerMetadata: IssuerMetadata,
    args: {
      userPinRequired?: boolean
      stateManager: IStateManager<CredentialOfferState>
      nonceManager: IStateManager<CNonceState>
      callback?: CredentialIssuerCallback
      verifyCallback?: JWTVerifyCallback
    }
  ) {
    this._issuerMetadata = issuerMetadata
    this._stateManager = args.stateManager
    this.nonceManager = args.nonceManager
    this._userPinRequired = args && args.userPinRequired ? args.userPinRequired : false
    this._issuerCallback = args?.callback
    this._verifyCallback = args?.verifyCallback
  }

  public get credentialOfferStateManager(): IStateManager<CredentialOfferState> {
    return this._stateManager
  }

  public get nonceStateManager(): IStateManager<CNonceState> {
    return this.nonceManager
  }

  public getIssuerMetadata() {
    return this._issuerMetadata
  }

  /**
   * issueCredentialFromIssueRequest
   * @param opts issuerREquestParams
   *  - issueCredentialsRequest the credential request
   *  - issuerState the state of the issuer
   *  - jwtVerifyCallback callback that verifies the Proof of Possession JWT
   *  - issuerCallback callback to issue a Verifiable Credential
   *  - cNonce an existing c_nonce
   */
  public async issueCredentialFromIssueRequest(opts: {
    issueCredentialRequest: CredentialRequest
    issuerState: string
    jwtVerifyCallback?: JWTVerifyCallback
    issuerCallback?: CredentialIssuerCallback
    cNonce?: string
  }): Promise<CredentialResponse> {
    const { clientId, grants } = await this.retrieveGrantsFromClient(opts.issuerState)
    await this.validateJWT(opts.issueCredentialRequest, grants, clientId, opts.jwtVerifyCallback)
    if (this.isMetadataSupportCredentialRequestFormat(opts.issueCredentialRequest.format)) {
      const cNonce = opts.cNonce ? opts.cNonce : v4()
      await this.nonceManager.setState(cNonce, { cNonce, createdOn: +new Date() })

      const compareArrays = (a: unknown[], b: unknown[]): boolean =>
        a.length === b.length && a.every((element: unknown): boolean => b.includes(element))

      if (opts.issueCredentialRequest.format === CredentialFormat.jwt_vc_json) {
        const supportedMatchingCredentials = this._issuerMetadata.credentials_supported.find(
          (a) =>
            a.format === opts.issueCredentialRequest.format &&
            compareArrays(
              a.types,
              Array.isArray(opts.issueCredentialRequest.type) ? opts.issueCredentialRequest.type : [opts.issueCredentialRequest.type]
            ) &&
            compareArrays(
              Object.keys((opts.issueCredentialRequest.credentialSubject as IssuerCredentialSubject) ?? {}),
              Object.keys(a.credentialSubject ?? {})
            )
        )
        if (supportedMatchingCredentials) {
          // TODO issue credential
          const credential = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            type: Array.isArray(opts.issueCredentialRequest.type) ? opts.issueCredentialRequest.type : [opts.issueCredentialRequest.type],
            issuer: this._issuerMetadata.credential_issuer,
            issuanceDate: new Date().toISOString(),
            credentialSubject: opts.issueCredentialRequest.credentialSubject as IssuerCredentialSubject,
          }
          const vc = await this.issueCredential({ credentialRequest: opts.issueCredentialRequest, credential }, opts.issuerCallback)
          // TODO implement acceptance_token (deferred response)
          // TODO update verification accordingly
          if (!vc) {
            // credential: OPTIONAL. Contains issued Credential. MUST be present when acceptance_token is not returned. MAY be a JSON string or a JSON object, depending on the Credential format. See Appendix E for the Credential format specific encoding requirements
            throw new Error(CREDENTIAL_MISSING_ERROR)
          }
          return {
            credential: vc,
            format: opts.issueCredentialRequest.format,
            c_nonce: cNonce,
            c_nonce_expires_in: this._cNonceExpiresIn,
          }
        }
      } else {
        throw new Error(`${opts.issueCredentialRequest.format}: credential format not supported`)
      }
    }
    throw new Error(TokenErrorResponse.invalid_request)
  }

  private async retrieveGrantsFromClient(issuerState: string): Promise<{ clientId?: string; grants?: Grant }> {
    const credentialOfferState: CredentialOfferState | undefined = await this._stateManager.getAssertedState(issuerState)
    const clientId = credentialOfferState?.clientId
    const grants = credentialOfferState?.credentialOffer?.grants
    if (!grants?.authorization_code?.issuer_state || !grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code']) {
      throw new Error(GRANTS_MUST_NOT_BE_UNDEFINED)
    }
    return { clientId, grants }
  }

  private async validateJWT(
    issueCredentialRequest: CredentialRequest,
    grants?: Grant,
    clientId?: string,
    jwtVerifyCallback?: JWTVerifyCallback
  ): Promise<void> {
    if (
      (!Array.isArray(issueCredentialRequest.format) && issueCredentialRequest.format === CredentialFormat.jwt_vc_json) ||
      issueCredentialRequest.format === CredentialFormat.jwt_vc_json_ld
    ) {
      issueCredentialRequest.proof.jwt

      if (!this._verifyCallback && !jwtVerifyCallback) {
        throw new Error(JWT_VERIFY_CONFIG_ERROR)
      }

      const { payload, header }: Jwt = jwtVerifyCallback
        ? await jwtVerifyCallback(issueCredentialRequest.proof)
        : await this._verifyCallback!(issueCredentialRequest.proof)

      const { typ, alg, kid, jwk, x5c } = header

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
      // https://www.rfc-editor.org/rfc/rfc6749.html#section-3.2.1
      // A client MAY use the "client_id" request parameter to identify itself
      // when sending requests to the token endpoint.  In the
      // "authorization_code" "grant_type" request to the token endpoint, an
      // unauthenticated client MUST send its "client_id" to prevent itself
      // from inadvertently accepting a code intended for a client with a
      // different "client_id".  This protects the client from substitution of
      // the authentication code.  (It provides no additional security for the
      // protected resource.)
      if (!iss && grants?.authorization_code) {
        throw new Error(NO_ISS_IN_AUTHORIZATION_CODE_CONTEXT)
      }
      // iss: OPTIONAL (string). The value of this claim MUST be the client_id of the client making the credential request.
      // This claim MUST be omitted if the Access Token authorizing the issuance call was obtained from a Pre-Authorized Code Flow through anonymous access to the Token Endpoint.
      // TODO We need to investigate further what the comment above means, because it's not clear if the client or the user may be authorized anonymously
      // if (iss && grants && grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']) {
      //   throw new Error(ISS_PRESENT_IN_PRE_AUTHORIZED_CODE_CONTEXT)
      // }
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
