import * as process from 'process'

import {
  Alg,
  ALG_ERROR,
  AUD_ERROR,
  CNonceState,
  CREDENTIAL_MISSING_ERROR,
  CredentialIssuerCallback,
  CredentialIssuerMetadata,
  CredentialOfferPayloadV1_0_11,
  CredentialOfferSession,
  CredentialOfferV1_0_11,
  CredentialRequest,
  CredentialResponse,
  Grant,
  GRANTS_MUST_NOT_BE_UNDEFINED,
  IAT_ERROR,
  ISS_MUST_BE_CLIENT_ID,
  ISSUER_CONFIG_ERROR,
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
} from '@sphereon/oid4vci-common'
import { URIState } from '@sphereon/oid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'
import { v4 } from 'uuid'

import { createCredentialOfferObject, createCredentialOfferURIFromObject } from './functions'
import { LookupStateManager } from './state-manager/LookupStateManager'

const SECOND = 1000

export class VcIssuer {
  private readonly _issuerMetadata: CredentialIssuerMetadata
  private readonly _userPinRequired: boolean
  private readonly _issuerCallback?: CredentialIssuerCallback
  private readonly _verifyCallback?: JWTVerifyCallback
  private readonly _credentialOfferSessions: IStateManager<CredentialOfferSession>
  private readonly _cNonces: IStateManager<CNonceState>
  private readonly _uris?: IStateManager<URIState>
  private readonly _cNonceExpiresIn: number

  constructor(
    issuerMetadata: CredentialIssuerMetadata,
    args: {
      userPinRequired?: boolean
      credentialOfferSessions: IStateManager<CredentialOfferSession>
      cNonces: IStateManager<CNonceState>
      uris?: IStateManager<URIState>
      callback?: CredentialIssuerCallback
      verifyCallback?: JWTVerifyCallback
      cNonceExpiresIn?: number | undefined // expiration duration in seconds
    }
  ) {
    this._issuerMetadata = issuerMetadata
    this._credentialOfferSessions = args.credentialOfferSessions
    this._cNonces = args.cNonces
    this._uris = args.uris
    this._userPinRequired = args?.userPinRequired ?? false
    this._issuerCallback = args?.callback
    this._verifyCallback = args?.verifyCallback
    this._cNonceExpiresIn =
      ((args?.cNonceExpiresIn ?? (process.env.C_NONCE_EXPIRES_IN ? parseInt(process.env.C_NONCE_EXPIRES_IN) : 90)) as number) * SECOND
  }

  public getCredentialOfferSessionById(id: string): Promise<CredentialOfferSession> {
    if (!this.uris) {
      throw Error('Cannnot lookup credential offer by id, if URI state manager is not set')
    }
    return new LookupStateManager<URIState, CredentialOfferSession>(this.uris, this._credentialOfferSessions, 'uri').getAsserted(id)
  }

  public async createCredentialOfferURI(opts: {
    grant: Grant
    issuerState?: string

    credentialOffer?: CredentialOfferPayloadV1_0_11
    credentialOfferUri?: string
    scheme?: string
    preAuthorizedCode?: string
    userPinRequired?: boolean
  }): Promise<string> {
    const credentialOffer = createCredentialOfferObject(this._issuerMetadata, {
      ...opts,
      userPinRequired: this._userPinRequired ?? opts?.userPinRequired,
    })
    const id = credentialOffer.grant.authorization_code
      ? credentialOffer.grant.authorization_code.issuer_state
      : credentialOffer.grant['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code']
    if (!id) {
      throw Error(`No grant state or pre-authorized code could be deduced`)
    }
    let userPin: number | undefined
    // todo: Double check this can only happen in pre-auth flow and if so make sure to not do the below when in a state is present (authorized flow)
    if (opts?.userPinRequired) {
      userPin = Math.round(9999 * Math.random())
    }
    const createdOn = +new Date()
    if (opts?.credentialOfferUri) {
      if (!this.uris) {
        throw Error('No URI state manager set, whilst apparently credential offer URIs are being used')
      }
      this.uris.set(opts.credentialOfferUri, { uri: opts.credentialOfferUri, createdOn, id })
    }

    this.credentialOfferSessions.set(id, {
      id,
      createdOn,
      ...(userPin && { userPin }),
      credentialOffer: {
        credential_offer: credentialOffer.credential_offer,
        credential_offer_uri: credentialOffer.credential_offer_uri,
      } as CredentialOfferV1_0_11,
    })

    return createCredentialOfferURIFromObject(credentialOffer)
  }

  /**
   * issueCredentialFromIssueRequest
   * @param opts issuerRequestParams
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
      await this._cNonces.set(cNonce, { cNonce, createdOn: +new Date() })
      const credential = await this.issueCredential({ credentialRequest: opts.issueCredentialRequest }, opts.issuerCallback)
      // TODO implement acceptance_token (deferred response)
      // TODO update verification accordingly
      if (!credential) {
        // credential: OPTIONAL. Contains issued Credential. MUST be present when acceptance_token is not returned. MAY be a JSON string or a JSON object, depending on the Credential format. See Appendix E for the Credential format specific encoding requirements
        throw new Error(CREDENTIAL_MISSING_ERROR)
      }
      return {
        credential,
        format: opts.issueCredentialRequest.format,
        c_nonce: cNonce,
        c_nonce_expires_in: this._cNonceExpiresIn,
      }
    }
    throw new Error(TokenErrorResponse.invalid_request)
  }

  private async retrieveGrantsFromClient(issuerState: string): Promise<{ clientId?: string; grants?: Grant }> {
    const credentialOfferState: CredentialOfferSession | undefined = await this._credentialOfferSessions.getAsserted(issuerState)
    const clientId = credentialOfferState?.clientId
    const grants = credentialOfferState?.credentialOffer?.credential_offer?.grants
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
    if ((!Array.isArray(issueCredentialRequest.format) && issueCredentialRequest.format === 'jwt') || issueCredentialRequest.format === 'jwt_vc') {
      issueCredentialRequest.proof.jwt

      if (typeof this._verifyCallback !== 'function' && typeof jwtVerifyCallback !== 'function') {
        throw new Error(JWT_VERIFY_CONFIG_ERROR)
      }

      const { payload, header }: Jwt = jwtVerifyCallback
        ? await jwtVerifyCallback(issueCredentialRequest.proof)
        : // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          await this._verifyCallback!(issueCredentialRequest.proof)

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

  get userPinRequired(): boolean {
    return this._userPinRequired
  }

  get issuerCallback(): CredentialIssuerCallback | undefined {
    return this._issuerCallback
  }

  get verifyCallback(): JWTVerifyCallback | undefined {
    return this._verifyCallback
  }

  get uris(): IStateManager<URIState> | undefined {
    return this._uris
  }

  get cNonceExpiresIn(): number {
    return this._cNonceExpiresIn
  }

  public get credentialOfferSessions(): IStateManager<CredentialOfferSession> {
    return this._credentialOfferSessions
  }

  public get cNonces(): IStateManager<CNonceState> {
    return this._cNonces
  }

  public get issuerMetadata() {
    return this._issuerMetadata
  }
}
