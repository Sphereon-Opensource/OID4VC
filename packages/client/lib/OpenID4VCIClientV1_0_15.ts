import { CreateDPoPClientOpts, JWK } from '@sphereon/oid4vc-common'
import {
  AccessTokenRequestOpts,
  AccessTokenResponse,
  Alg,
  AuthorizationChallengeCodeResponse,
  AuthorizationChallengeErrorResponse,
  AuthorizationChallengeRequestOpts,
  AuthorizationRequestOpts,
  AuthorizationResponse,
  AuthorizationServerOpts,
  AuthzFlowType,
  CodeChallengeMethod,
  CredentialConfigurationSupportedV1_0_15,
  CredentialOfferPayloadV1_0_15,
  CredentialOfferRequestWithBaseUrl,
  CredentialResponseV1_0_15,
  DefaultURISchemes,
  DPoPResponseParams,
  EndpointMetadataResultV1_0_15,
  ExperimentalSubjectIssuance,
  getClientIdFromCredentialOfferPayload,
  getIssuerFromCredentialOfferPayload,
  getSupportedCredentials,
  KID_JWK_X5C_ERROR,
  NotificationRequest,
  NotificationResponseResult,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  PKCEOpts,
  ProofOfPossessionCallbacks,
  toAuthorizationResponsePayload
} from '@sphereon/oid4vci-common'
import { CredentialFormat, Loggers } from '@sphereon/ssi-types'

import { AccessTokenClient } from './AccessTokenClient'
import { acquireAuthorizationChallengeAuthCode, createAuthorizationRequestUrl } from './AuthorizationCodeClient'
import { CredentialOfferClientV1_0_15 } from './CredentialOfferClientV1_0_15'
import { CredentialRequestClientBuilderV1_0_15 } from './CredentialRequestClientBuilderV1_0_15'
import { CredentialRequestOpts } from './CredentialRequestClient'
import { MetadataClientV1_0_15 } from './MetadataClientV1_0_15'
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder'
import { generateMissingPKCEOpts, sendNotification } from './functions'
import { acquireNonceFromAuthorizationServer } from './NonceClient'

const logger = Loggers.DEFAULT.get('sphereon:oid4vci:v15')

export interface OpenID4VCIClientStateV1_0_15 {
  credentialIssuer: string
  credentialOffer?: CredentialOfferRequestWithBaseUrl
  clientId?: string
  kid?: string
  jwk?: JWK
  alg?: Alg | string
  endpointMetadata?: EndpointMetadataResultV1_0_15
  accessTokenResponse?: AccessTokenResponse
  dpopResponseParams?: DPoPResponseParams
  authorizationRequestOpts?: AuthorizationRequestOpts
  authorizationCodeResponse?: AuthorizationResponse | AuthorizationChallengeCodeResponse
  pkce: PKCEOpts
  accessToken?: string
  authorizationURL?: string
  // New in v15
  cachedCNonce?: string
  keyAttestation?: string // JWT format key attestation
}

export class OpenID4VCIClientV1_0_15 {
  private readonly _state: OpenID4VCIClientStateV1_0_15

  private constructor({
                        credentialOffer,
                        clientId,
                        kid,
                        alg,
                        credentialIssuer,
                        pkce,
                        authorizationRequest,
                        jwk,
                        endpointMetadata,
                        accessTokenResponse,
                        authorizationRequestOpts,
                        authorizationCodeResponse,
                        authorizationURL,
                        keyAttestation
                      }: {
    credentialOffer?: CredentialOfferRequestWithBaseUrl
    kid?: string
    alg?: Alg | string
    clientId?: string
    credentialIssuer?: string
    pkce?: PKCEOpts
    authorizationRequest?: AuthorizationRequestOpts
    jwk?: JWK
    endpointMetadata?: EndpointMetadataResultV1_0_15
    accessTokenResponse?: AccessTokenResponse
    authorizationRequestOpts?: AuthorizationRequestOpts
    authorizationCodeResponse?: AuthorizationResponse | AuthorizationChallengeCodeResponse
    authorizationURL?: string
    keyAttestation?: string
  }) {
    const issuer = credentialIssuer ?? (credentialOffer ? getIssuerFromCredentialOfferPayload(credentialOffer.credential_offer) : undefined)
    if (!issuer) {
      throw Error('No credential issuer supplied or deduced from offer')
    }
    this._state = {
      credentialOffer,
      credentialIssuer: issuer,
      kid,
      alg,
      clientId: clientId ?? (credentialOffer && getClientIdFromCredentialOfferPayload(credentialOffer.credential_offer)) ?? kid?.split('#')[0],
      pkce: { disabled: false, codeChallengeMethod: CodeChallengeMethod.S256, ...pkce },
      authorizationRequestOpts,
      authorizationCodeResponse,
      jwk,
      endpointMetadata,
      accessTokenResponse,
      authorizationURL,
      keyAttestation
    }

    if (!this._state.authorizationRequestOpts) {
      this._state.authorizationRequestOpts = this.syncAuthorizationRequestOpts(authorizationRequest)
    }
    logger.debug(`Authorization req options: ${JSON.stringify(this._state.authorizationRequestOpts, null, 2)}`)
  }

  public static async fromCredentialIssuer({
                                             kid,
                                             alg,
                                             retrieveServerMetadata,
                                             clientId,
                                             credentialIssuer,
                                             pkce,
                                             authorizationRequest,
                                             createAuthorizationRequestURL,
                                             keyAttestation
                                           }: {
    credentialIssuer: string
    kid?: string
    alg?: Alg | string
    retrieveServerMetadata?: boolean
    clientId?: string
    createAuthorizationRequestURL?: boolean
    authorizationRequest?: AuthorizationRequestOpts
    pkce?: PKCEOpts
    keyAttestation?: string
  }) {
    const client = new OpenID4VCIClientV1_0_15({
      kid,
      alg,
      clientId: clientId ?? authorizationRequest?.clientId,
      credentialIssuer,
      pkce,
      authorizationRequest,
      keyAttestation
    })
    if (retrieveServerMetadata !== false) {
      await client.retrieveServerMetadata()
    }
    if (createAuthorizationRequestURL !== false) {
      await client.createAuthorizationRequestUrl({ authorizationRequest, pkce })
    }
    return client
  }

  public static async fromState({ state }: {
    state: OpenID4VCIClientStateV1_0_15 | string
  }): Promise<OpenID4VCIClientV1_0_15> {
    const clientState = typeof state === 'string' ? JSON.parse(state) : state
    return new OpenID4VCIClientV1_0_15(clientState)
  }

  public static async fromURI({
                                uri,
                                kid,
                                alg,
                                retrieveServerMetadata,
                                clientId,
                                pkce,
                                createAuthorizationRequestURL,
                                authorizationRequest,
                                resolveOfferUri,
                                keyAttestation
                              }: {
    uri: string
    kid?: string
    alg?: Alg | string
    retrieveServerMetadata?: boolean
    createAuthorizationRequestURL?: boolean
    resolveOfferUri?: boolean
    pkce?: PKCEOpts
    clientId?: string
    authorizationRequest?: AuthorizationRequestOpts
    keyAttestation?: string
  }): Promise<OpenID4VCIClientV1_0_15> {
    const credentialOfferClient = await CredentialOfferClientV1_0_15.fromURI(uri, { resolve: resolveOfferUri })
    const client = new OpenID4VCIClientV1_0_15({
      credentialOffer: credentialOfferClient,
      kid,
      alg,
      clientId: clientId ?? authorizationRequest?.clientId ?? credentialOfferClient.clientId,
      pkce,
      authorizationRequest,
      keyAttestation
    })

    if (retrieveServerMetadata !== false) {
      await client.retrieveServerMetadata()
    }
    if (
      credentialOfferClient.supportedFlows.includes(AuthzFlowType.AUTHORIZATION_CODE_FLOW) &&
      createAuthorizationRequestURL !== false
    ) {
      await client.createAuthorizationRequestUrl({ authorizationRequest, pkce })
      logger.debug(`Authorization Request URL: ${client._state.authorizationURL}`)
    }

    return client
  }

  public async createAuthorizationRequestUrl(opts?: {
    authorizationRequest?: AuthorizationRequestOpts;
    pkce?: PKCEOpts
  }): Promise<string> {
    if (!this._state.authorizationURL) {
      this.calculatePKCEOpts(opts?.pkce)
      this._state.authorizationRequestOpts = this.syncAuthorizationRequestOpts(opts?.authorizationRequest)
      if (!this._state.authorizationRequestOpts) {
        throw Error(`No Authorization Request options present or provided in this call`)
      }

      if (
        this._state.endpointMetadata?.credentialIssuerMetadata &&
        'authorization_endpoint' in this._state.endpointMetadata.credentialIssuerMetadata
      ) {
        this._state.endpointMetadata.authorization_endpoint = this._state.endpointMetadata.credentialIssuerMetadata.authorization_endpoint as string
      }

      this._state.authorizationURL = await createAuthorizationRequestUrl({
        pkce: this._state.pkce,
        endpointMetadata: this.endpointMetadata,
        authorizationRequest: this._state.authorizationRequestOpts,
        credentialOffer: this.credentialOffer,
        credentialConfigurationSupported: this.getCredentialsSupported(false) as Record<string, CredentialConfigurationSupportedV1_0_15>
      })
    }
    return this._state.authorizationURL
  }

  public async retrieveServerMetadata(): Promise<EndpointMetadataResultV1_0_15> {
    this.assertIssuerData()
    if (!this._state.endpointMetadata) {
      if (this.credentialOffer) {
        this._state.endpointMetadata = await MetadataClientV1_0_15.retrieveAllMetadataFromCredentialOffer(this.credentialOffer)
      } else if (this._state.credentialIssuer) {
        this._state.endpointMetadata = await MetadataClientV1_0_15.retrieveAllMetadata(this._state.credentialIssuer)
      } else {
        throw Error(`Cannot retrieve issuer metadata without either a credential offer, or issuer value`)
      }
    }

    return this.endpointMetadata
  }

  public async acquireNonce(): Promise<string> {
    const response = await acquireNonceFromAuthorizationServer({
      metadata: this.endpointMetadata,
      issuerOpts: { issuer: this.getIssuer(), fetchMetadata: false }
    })

    if (response.errorBody) {
      logger.debug(`Nonce request error:\r\n${JSON.stringify(response.errorBody)}`)
      return Promise.reject(
        Error(
          `Retrieving a nonce from ${this._state.endpointMetadata?.credentialIssuerMetadata?.nonce_endpoint} for issuer ${this.getIssuer()} failed with error: ${response.errorBody.error}${response.errorBody.error_description ? ` - ${response.errorBody.error_description}` : ''}`
        )
      )
    } else if (!response.successBody) {
      logger.debug(`Nonce request error. No success body`)
      return Promise.reject(
        Error(
          `Retrieving a nonce from ${this._state.endpointMetadata?.credentialIssuerMetadata?.nonce_endpoint} for issuer ${this.getIssuer()} failed as there was no success response body`
        )
      )
    }

    this._state.cachedCNonce = response.successBody.c_nonce
    return response.successBody.c_nonce
  }

  private calculatePKCEOpts(pkce?: PKCEOpts) {
    this._state.pkce = generateMissingPKCEOpts({ ...this._state.pkce, ...pkce })
  }

  public async acquireAuthorizationChallengeCode(opts?: AuthorizationChallengeRequestOpts): Promise<AuthorizationChallengeCodeResponse> {
    const response = await acquireAuthorizationChallengeAuthCode({
      metadata: this.endpointMetadata,
      credentialIssuer: this.getIssuer(),
      clientId: this._state.clientId ?? this._state.authorizationRequestOpts?.clientId,
      ...opts
    })

    if (response.errorBody) {
      logger.debug(`Authorization code error:\r\n${JSON.stringify(response.errorBody)}`)
      const error = response.errorBody as AuthorizationChallengeErrorResponse
      return Promise.reject(error)
    } else if (!response.successBody) {
      logger.debug(`Authorization code error. No success body`)
      return Promise.reject(
        Error(
          `Retrieving an authorization code token from ${this._state.endpointMetadata?.authorization_challenge_endpoint} for issuer ${this.getIssuer()} failed as there was no success response body`
        )
      )
    }

    return { ...response.successBody }
  }

  public async acquireAccessToken(
    opts?: Omit<AccessTokenRequestOpts, 'credentialOffer' | 'credentialIssuer' | 'metadata' | 'additionalParams'> & {
      clientId?: string
      authorizationResponse?: string | AuthorizationResponse | AuthorizationChallengeCodeResponse
      additionalRequestParams?: Record<string, any>
    }
  ): Promise<AccessTokenResponse & { params?: DPoPResponseParams }> {
    const { pin, clientId = this._state.clientId ?? this._state.authorizationRequestOpts?.clientId } = opts ?? {}
    let { redirectUri } = opts ?? {}

    const code = this.getAuthorizationCode(opts?.authorizationResponse, opts?.code)

    if (opts?.codeVerifier) {
      this._state.pkce.codeVerifier = opts.codeVerifier
    }
    this.assertIssuerData()

    const asOpts: AuthorizationServerOpts = { ...opts?.asOpts }
    const kid = asOpts.clientOpts?.kid ?? this._state.kid ?? this._state.authorizationRequestOpts?.requestObjectOpts?.kid
    const clientAssertionType =
      asOpts.clientOpts?.clientAssertionType ??
      (kid && clientId && typeof asOpts.clientOpts?.signCallbacks?.signCallback === 'function'
        ? 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        : undefined)

    if (this.isEBSI() || (clientId && kid)) {
      if (!clientId) {
        throw Error(`Client id expected for EBSI`)
      }
      asOpts.clientOpts = {
        ...asOpts.clientOpts,
        clientId,
        ...(kid && { kid }),
        ...(clientAssertionType && { clientAssertionType }),
        signCallbacks: asOpts.clientOpts?.signCallbacks ?? this._state.authorizationRequestOpts?.requestObjectOpts?.signCallbacks
      }
    }

    if (clientId) {
      this._state.clientId = clientId
      if (!asOpts.clientOpts) {
        asOpts.clientOpts = { clientId }
      }
      asOpts.clientOpts.clientId = clientId
    }

    if (!this._state.accessTokenResponse) {
      const accessTokenClient = new AccessTokenClient()

      if (redirectUri && redirectUri !== this._state.authorizationRequestOpts?.redirectUri) {
        console.log(
          `Redirect URI mismatch between access-token (${redirectUri}) and authorization request (${this._state.authorizationRequestOpts?.redirectUri}). According to the specification that is not allowed.`
        )
      }
      if (this._state.authorizationRequestOpts?.redirectUri && !redirectUri) {
        redirectUri = this._state.authorizationRequestOpts.redirectUri
      }

      const response = await accessTokenClient.acquireAccessToken({
        credentialOffer: this.credentialOffer,
        metadata: this.endpointMetadata,
        credentialIssuer: this.getIssuer(),
        pin,
        ...(!this._state.pkce.disabled && { codeVerifier: this._state.pkce.codeVerifier }),
        code,
        redirectUri,
        asOpts,
        ...(opts?.createDPoPOpts && { createDPoPOpts: opts.createDPoPOpts }),
        ...(opts?.additionalRequestParams && { additionalParams: opts.additionalRequestParams })
      })

      if (response.errorBody) {
        logger.debug(`Access token error:\r\n${JSON.stringify(response.errorBody)}`)
        throw Error(
          `Retrieving an access token from ${this._state.endpointMetadata?.token_endpoint} for issuer ${this.getIssuer()} failed with status: ${
            response.origResponse.status
          }`
        )
      } else if (!response.successBody) {
        logger.debug(`Access token error. No success body`)
        throw Error(
          `Retrieving an access token from ${
            this._state.endpointMetadata?.token_endpoint
          } for issuer ${this.getIssuer()} failed as there was no success response body`
        )
      }
      this._state.accessTokenResponse = response.successBody
      this._state.dpopResponseParams = response.params
      this._state.accessToken = response.successBody.access_token
    }

    return { ...this.accessTokenResponse, ...(this.dpopResponseParams && { params: this.dpopResponseParams }) }
  }

  public async acquireCredentials({
                                    credentialIdentifier,
                                    credentialConfigurationId,
                                    credentialTypes,
                                    context,
                                    proofCallbacks,
                                    format,
                                    kid,
                                    jwk,
                                    alg,
                                    jti,
                                    deferredCredentialAwait,
                                    deferredCredentialIntervalInMS,
                                    createDPoPOpts
                                  }: {
    credentialIdentifier?: string
    credentialConfigurationId?: string
    credentialTypes?: string | string[]
    context?: string[]
    proofCallbacks: ProofOfPossessionCallbacks
    format: CredentialFormat | OID4VCICredentialFormat
    kid?: string
    jwk?: JWK
    alg?: Alg | string
    jti?: string
    deferredCredentialAwait?: boolean
    deferredCredentialIntervalInMS?: number
    createDPoPOpts?: CreateDPoPClientOpts
  }): Promise<CredentialResponseV1_0_15 & { params?: DPoPResponseParams; access_token: string }> {
    if ([jwk, kid].filter((v) => v !== undefined).length > 1) {
      throw new Error(KID_JWK_X5C_ERROR + `. jwk: ${jwk !== undefined}, kid: ${kid !== undefined}`)
    }

    if (alg) this._state.alg = alg
    if (jwk) this._state.jwk = jwk
    if (kid) this._state.kid = kid

    const requestBuilder = this.credentialOffer
      ? CredentialRequestClientBuilderV1_0_15.fromCredentialOffer({
        credentialOffer: this.credentialOffer,
        metadata: this.endpointMetadata
      })
      : CredentialRequestClientBuilderV1_0_15.fromCredentialIssuer({
        credentialIssuer: this.getIssuer(),
        credentialTypes,
        credentialIdentifier,
        credentialConfigurationId,
        metadata: this.endpointMetadata,
        version: this.version()
      })

    // Set credential identifier or configuration ID
    if (credentialIdentifier) {
      requestBuilder.withCredentialIdentifier(credentialIdentifier)
    } else if (credentialConfigurationId) {
      requestBuilder.withCredentialConfigurationId(credentialConfigurationId)
    }

    const issuerState =
      this.issuerSupportedFlowTypes().includes(AuthzFlowType.AUTHORIZATION_CODE_FLOW) &&
      this._state.authorizationCodeResponse &&
      !this._state.cachedCNonce &&
      this._state.credentialOffer?.issuerState
        ? this._state.credentialOffer.issuerState
        : undefined
    requestBuilder.withIssuerState(issuerState)

    requestBuilder.withTokenFromResponse(this.accessTokenResponse)
    requestBuilder.withDeferredCredentialAwait(deferredCredentialAwait ?? false, deferredCredentialIntervalInMS)

    let subjectIssuance: ExperimentalSubjectIssuance | undefined
    if (this.endpointMetadata?.credentialIssuerMetadata) {
      const metadata = this.endpointMetadata.credentialIssuerMetadata

      if (metadata.credential_configurations_supported) {
        const configId = credentialConfigurationId ?? credentialIdentifier
        if (configId && metadata.credential_configurations_supported[configId]) {
          const config = metadata.credential_configurations_supported[configId]
          if (config.credential_subject_issuance) {
            const subjIssuance = config.credential_subject_issuance as any
            if (subjIssuance.subject_proof_mode && subjIssuance.notification_events_supported) {
              subjectIssuance = {
                credential_subject_issuance: {
                  subject_proof_mode: subjIssuance.subject_proof_mode,
                  notification_events_supported: subjIssuance.notification_events_supported
                }
              }
            }
          }
        }
      }
    }

    if (subjectIssuance) {
      requestBuilder.withSubjectIssuance(subjectIssuance)
    }

    const credentialRequestClient = requestBuilder.build()

    // Acquire fresh nonce if needed
    if (!this._state.cachedCNonce) {
      await this.acquireNonce()
    }

    const proofBuilder = ProofOfPossessionBuilder.fromAccessTokenResponse({
      accessTokenResponse: { ...this.accessTokenResponse, c_nonce: this._state.cachedCNonce },
      callbacks: proofCallbacks,
      version: this.version()
    })
      .withIssuer(this.getIssuer())
      .withAlg(this.alg)

    if (this._state.jwk) {
      proofBuilder.withJWK(this._state.jwk)
    }
    if (this._state.kid) {
      proofBuilder.withKid(this._state.kid)
    }
    if (this.clientId) {
      proofBuilder.withClientId(this.clientId)
    }
    if (jti) {
      proofBuilder.withJti(jti)
    }

    const response = await credentialRequestClient.acquireCredentialsUsingProof({
      proofInput: proofBuilder,
      credentialIdentifier,
      credentialTypes,
      context,
      format,
      subjectIssuance,
      createDPoPOpts
    })

    this._state.dpopResponseParams = response.params

    if (response.errorBody) {
      logger.debug(`Credential request error:\r\n${JSON.stringify(response.errorBody)}`)
      throw Error(
        `Retrieving a credential from ${this._state.endpointMetadata?.credential_endpoint} for issuer ${this.getIssuer()} failed with status: ${
          response.origResponse.status
        }`
      )
    } else if (!response.successBody) {
      logger.debug(`Credential request error. No success body`)
      throw Error(
        `Retrieving a credential from ${
          this._state.endpointMetadata?.credential_endpoint
        } for issuer ${this.getIssuer()} failed as there was no success response body`
      )
    }

    return {
      ...response.successBody, ...(this.dpopResponseParams && { params: this.dpopResponseParams }),
      access_token: response.access_token
    }
  }

  public async exportState(): Promise<string> {
    return JSON.stringify(this._state)
  }

  getCredentialsSupported(
    restrictToInitiationTypes?: boolean,
    format?: (OID4VCICredentialFormat | string) | (OID4VCICredentialFormat | string)[]
  ): Record<string, CredentialConfigurationSupportedV1_0_15> {
    return getSupportedCredentials({
      issuerMetadata: this.endpointMetadata.credentialIssuerMetadata,
      version: this.version(),
      format: format,
      types: restrictToInitiationTypes ? [this.getCredentialOfferConfigurationIds()] : undefined
    }) as Record<string, CredentialConfigurationSupportedV1_0_15>
  }

  public async sendNotification(
    credentialRequestOpts: Partial<CredentialRequestOpts>,
    request: NotificationRequest,
    accessToken?: string
  ): Promise<NotificationResponseResult> {
    return sendNotification(credentialRequestOpts, request, accessToken ?? this._state.accessToken ?? this._state.accessTokenResponse?.access_token)
  }

  getCredentialOfferConfigurationIds(): string[] {
    if (!this.credentialOffer) {
      return []
    }

    return (this.credentialOffer.credential_offer as CredentialOfferPayloadV1_0_15 | undefined)?.credential_configuration_ids ?? []
  }

  issuerSupportedFlowTypes(): AuthzFlowType[] {
    return (
      this.credentialOffer?.supportedFlows ??
      ((this._state.endpointMetadata?.credentialIssuerMetadata?.authorization_endpoint ?? this._state.endpointMetadata?.authorization_server)
        ? [AuthzFlowType.AUTHORIZATION_CODE_FLOW]
        : [])
    )
  }

  isFlowTypeSupported(flowType: AuthzFlowType): boolean {
    return this.issuerSupportedFlowTypes().includes(flowType)
  }

  get authorizationURL(): string | undefined {
    return this._state.authorizationURL
  }

  public hasAuthorizationURL(): boolean {
    return !!this.authorizationURL
  }

  get credentialOffer(): CredentialOfferRequestWithBaseUrl | undefined {
    return this._state.credentialOffer
  }

  public version(): OpenId4VCIVersion {
    return OpenId4VCIVersion.VER_1_0_15
  }

  public get endpointMetadata(): EndpointMetadataResultV1_0_15 {
    this.assertServerMetadata()
    return this._state.endpointMetadata!
  }

  get kid(): string {
    this.assertIssuerData()
    if (!this._state.kid) {
      throw new Error('No value for kid is supplied')
    }
    return this._state.kid
  }

  get alg(): string {
    this.assertIssuerData()
    if (!this._state.alg) {
      throw new Error('No value for alg is supplied')
    }
    return this._state.alg
  }

  set clientId(value: string | undefined) {
    this._state.clientId = value
  }

  get clientId(): string | undefined {
    return this._state.clientId
  }

  public hasAccessTokenResponse(): boolean {
    return !!this._state.accessTokenResponse
  }

  get accessTokenResponse(): AccessTokenResponse {
    this.assertAccessToken()
    return this._state.accessTokenResponse!
  }

  get dpopResponseParams(): DPoPResponseParams | undefined {
    return this._state.dpopResponseParams
  }

  public get state(): OpenID4VCIClientStateV1_0_15 {
    return this._state
  }

  public getIssuer(): string {
    this.assertIssuerData()
    return this._state.credentialIssuer
  }

  public getAccessTokenEndpoint(): string {
    this.assertIssuerData()
    return this.endpointMetadata?.token_endpoint ?? AccessTokenClient.determineTokenURL({ issuerOpts: { issuer: this.getIssuer() } })
  }

  public getCredentialEndpoint(): string {
    this.assertIssuerData()
    return this.endpointMetadata?.credential_endpoint ?? `${this.getIssuer()}/credential`
  }

  public getNonceEndpoint(): string | undefined {
    return this.endpointMetadata?.credentialIssuerMetadata?.nonce_endpoint
  }

  public hasNonceEndpoint(): boolean {
    return !!this.getNonceEndpoint()
  }

  public getAuthorizationChallengeEndpoint(): string | undefined {
    this.assertIssuerData()
    return this.endpointMetadata?.authorization_challenge_endpoint
  }

  public hasAuthorizationChallengeEndpoint(): boolean {
    return !!this.getAuthorizationChallengeEndpoint()
  }

  public hasDeferredCredentialEndpoint(): boolean {
    return !!this.endpointMetadata?.deferred_credential_endpoint
  }

  public getDeferredCredentialEndpoint(): string | undefined {
    this.assertIssuerData()
    return this.endpointMetadata?.deferred_credential_endpoint
  }

  public isEBSI() {
    return (
      this.clientId?.includes('ebsi') ||
      this._state.kid?.includes('did:ebsi:') ||
      this.getIssuer().includes('ebsi') ||
      this.endpointMetadata?.credentialIssuerMetadata?.authorization_endpoint?.includes('ebsi.eu') ||
      this.endpointMetadata?.credentialIssuerMetadata?.authorization_server?.includes('ebsi.eu')
    )
  }

  private assertIssuerData(): void {
    if (!this._state.credentialIssuer) {
      throw Error(`No credential issuer value present`)
    } else if (!this._state.credentialOffer && this._state.endpointMetadata && this.issuerSupportedFlowTypes().length === 0) {
      throw Error(`No issuance initiation or credential offer present`)
    }
  }

  private assertServerMetadata(): void {
    if (!this._state.endpointMetadata) {
      throw Error('No server metadata')
    }
  }

  private assertAccessToken(): void {
    if (!this._state.accessTokenResponse) {
      throw Error(`No access token present`)
    }
  }

  private syncAuthorizationRequestOpts(opts?: AuthorizationRequestOpts): AuthorizationRequestOpts {
    const requestObjectOpts = { ...this._state?.authorizationRequestOpts?.requestObjectOpts, ...opts?.requestObjectOpts }
    let authorizationRequestOpts = {
      ...this._state?.authorizationRequestOpts,
      ...opts,
      ...(requestObjectOpts && { requestObjectOpts })
    } as AuthorizationRequestOpts

    if (!authorizationRequestOpts) {
      authorizationRequestOpts = { redirectUri: `${DefaultURISchemes.CREDENTIAL_OFFER}://` }
    }

    const clientId = authorizationRequestOpts.clientId ?? this._state.clientId
    this._state.clientId = clientId
    authorizationRequestOpts.clientId = clientId
    return authorizationRequestOpts
  }

  private getAuthorizationCode = (
    authorizationResponse?: string | AuthorizationResponse | AuthorizationChallengeCodeResponse,
    code?: string
  ): string | undefined => {
    if (authorizationResponse) {
      this._state.authorizationCodeResponse = { ...toAuthorizationResponsePayload(authorizationResponse) }
    } else if (code) {
      this._state.authorizationCodeResponse = { code }
    }

    return (
      (this._state.authorizationCodeResponse as AuthorizationResponse)?.code ??
      (this._state.authorizationCodeResponse as AuthorizationChallengeCodeResponse)?.authorization_code
    )
  }
}
