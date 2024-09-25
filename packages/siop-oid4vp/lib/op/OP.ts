import { EventEmitter } from 'events'

import { joseExtractJWKS } from '@protokoll/core'
import { JarmClientMetadataParams, sendJarmAuthRequest } from '@protokoll/jarm'
import { JwtIssuer, uuidv4 } from '@sphereon/oid4vc-common'
import { IIssuerId } from '@sphereon/ssi-types'

import { AuthorizationRequest, URI, VerifyAuthorizationRequestOpts } from '../authorization-request'
import { mergeVerificationOpts } from '../authorization-request/Opts'
import {
  AuthorizationResponse,
  AuthorizationResponseOpts,
  AuthorizationResponseWithCorrelationId,
  PresentationExchangeResponseOpts,
} from '../authorization-response'
import { encodeJsonAsURI, post } from '../helpers'
import { authorizationRequestVersionDiscovery } from '../helpers/SIOPSpecVersion'
import {
  AuthorizationEvent,
  AuthorizationEvents,
  ContentType,
  JWK,
  ParsedAuthorizationRequestURI,
  RegisterEventListener,
  ResponseIss,
  ResponseMode,
  SIOPErrors,
  SIOPResonse,
  SupportedVersion,
  UrlEncodingFormat,
  Verification,
  VerifiedAuthorizationRequest,
} from '../types'

import { OPBuilder } from './OPBuilder'
import { createResponseOptsFromBuilderOrExistingOpts, createVerifyRequestOptsFromBuilderOrExistingOpts } from './Opts'

// The OP publishes the formats it supports using the vp_formats_supported metadata parameter as defined above in its "openid-configuration".
export class OP {
  private readonly _createResponseOptions: AuthorizationResponseOpts
  private readonly _verifyRequestOptions: Partial<VerifyAuthorizationRequestOpts>
  private readonly _eventEmitter?: EventEmitter

  private constructor(opts: { builder?: OPBuilder; responseOpts?: AuthorizationResponseOpts; verifyOpts?: VerifyAuthorizationRequestOpts }) {
    this._createResponseOptions = { ...createResponseOptsFromBuilderOrExistingOpts(opts) }
    this._verifyRequestOptions = { ...createVerifyRequestOptsFromBuilderOrExistingOpts(opts) }
    this._eventEmitter = opts.builder?.eventEmitter
  }

  /**
   * This method tries to infer the SIOP specs version based on the request payload.
   * If the version cannot be inferred or is not supported it throws an exception.
   * This method needs to be called to ensure the OP can handle the request
   * @param requestJwtOrUri
   * @param requestOpts
   */

  public async verifyAuthorizationRequest(
    requestJwtOrUri: string | URI,
    requestOpts?: { correlationId?: string; verification?: Verification },
  ): Promise<VerifiedAuthorizationRequest> {
    const correlationId = requestOpts?.correlationId || uuidv4()
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestJwtOrUri)
      .then((result: AuthorizationRequest) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_SUCCESS, { correlationId, subject: result })
        return result
      })
      .catch((error: Error) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_RECEIVED_FAILED, {
          correlationId,
          subject: requestJwtOrUri,
          error,
        })
        throw error
      })

    return authorizationRequest
      .verify(this.newVerifyAuthorizationRequestOpts({ ...requestOpts, correlationId }))
      .then((verifiedAuthorizationRequest: VerifiedAuthorizationRequest) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_SUCCESS, {
          correlationId,
          subject: verifiedAuthorizationRequest.authorizationRequest,
        })
        return verifiedAuthorizationRequest
      })
      .catch((error) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_REQUEST_VERIFIED_FAILED, {
          correlationId,
          subject: authorizationRequest,
          error,
        })
        throw error
      })
  }

  public async createAuthorizationResponse(
    verifiedAuthorizationRequest: VerifiedAuthorizationRequest,
    responseOpts: {
      jwtIssuer?: JwtIssuer
      version?: SupportedVersion
      correlationId?: string
      audience?: string
      issuer?: ResponseIss | string
      verification?: Verification
      presentationExchange?: PresentationExchangeResponseOpts
    },
  ): Promise<AuthorizationResponseWithCorrelationId> {
    if (
      verifiedAuthorizationRequest.correlationId &&
      responseOpts?.correlationId &&
      verifiedAuthorizationRequest.correlationId !== responseOpts.correlationId
    ) {
      throw new Error(
        `Request correlation id ${verifiedAuthorizationRequest.correlationId} is different from option correlation id ${responseOpts.correlationId}`,
      )
    }
    let version = responseOpts?.version
    const rpSupportedVersions = authorizationRequestVersionDiscovery(await verifiedAuthorizationRequest.authorizationRequest.mergedPayloads())
    if (version && rpSupportedVersions.length > 0 && !rpSupportedVersions.includes(version)) {
      throw Error(`RP does not support spec version ${version}, supported versions: ${rpSupportedVersions.toString()}`)
    } else if (!version) {
      version = rpSupportedVersions.reduce(
        (previous, current) => (current.valueOf() > previous.valueOf() ? current : previous),
        SupportedVersion.SIOPv2_ID1,
      )
    }
    const correlationId = responseOpts?.correlationId ?? verifiedAuthorizationRequest.correlationId ?? uuidv4()
    try {
      // IF using DIRECT_POST, the response_uri takes precedence over the redirect_uri
      let responseUri = verifiedAuthorizationRequest.responseURI
      if (verifiedAuthorizationRequest.authorizationRequestPayload.response_mode === ResponseMode.DIRECT_POST) {
        responseUri = verifiedAuthorizationRequest.authorizationRequestPayload.response_uri ?? responseUri
      }

      const response = await AuthorizationResponse.fromVerifiedAuthorizationRequest(
        verifiedAuthorizationRequest,
        this.newAuthorizationResponseOpts({
          ...responseOpts,
          version,
          correlationId,
        }),
        verifiedAuthorizationRequest.verifyOpts,
      )
      void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_SUCCESS, {
        correlationId,
        subject: response,
      })
      return { correlationId, response, responseURI: responseUri }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
      void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_CREATE_FAILED, {
        correlationId,
        subject: verifiedAuthorizationRequest.authorizationRequest,
        error,
      })
      throw error
    }
  }

  // TODO SK Can you please put some documentation on it?
  public async submitAuthorizationResponse(
    authorizationResponse: AuthorizationResponseWithCorrelationId,
    clientMetadata?: {
      jwks?: { keys: JWK[] }
      jwks_uri?: string
    } & JarmClientMetadataParams,
  ): Promise<Response> {
    const { correlationId, response } = authorizationResponse
    if (!correlationId) {
      throw Error('No correlation Id provided')
    }

    const isJarmResponseMode = (responseMode: string): responseMode is 'jwt' | 'direct_post.jwt' | 'query.jwt' | 'fragment.jwt' => {
      return responseMode === ResponseMode.DIRECT_POST_JWT || responseMode === ResponseMode.QUERY_JWT || responseMode === ResponseMode.FRAGMENT_JWT
    }

    const responseMode = response.options.responseMode

    if (
      !response ||
      (response.options?.responseMode &&
        !(
          responseMode === ResponseMode.POST ||
          responseMode === ResponseMode.FORM_POST ||
          responseMode === ResponseMode.DIRECT_POST ||
          isJarmResponseMode(responseMode)
        ))
    ) {
      throw new Error(SIOPErrors.BAD_PARAMS)
    }

    const payload = response.payload
    const idToken = await response.idToken?.payload()
    const responseUri = authorizationResponse.responseURI ?? idToken?.aud
    if (!responseUri) {
      throw Error('No response URI present')
    }

    if (isJarmResponseMode(responseMode)) {
      if (!clientMetadata) {
        throw new Error(`Sending an authorization response with response_mode '${responseMode}' requires providing client_metadata`)
      }

      if (!this._createResponseOptions.encryptJwtCallback) {
        throw new Error(`Sending an authorization response with response_mode '${responseMode}' requires providing an encryptJwtCallback`)
      }

      // The client metadata will be parsed in the joseExtractJWKS function
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const jwks = await joseExtractJWKS(clientMetadata as any)
      const dectyptionJwk = jwks.keys.find((key) => key.use === 'enc')
      if (!dectyptionJwk) {
        throw new Error('No decryption could be extracted from the client metadata')
      }

      const { jwe } = await this.createResponseOptions.encryptJwtCallback({
        jwk: dectyptionJwk,
        plaintext: JSON.stringify(response.payload),
      })

      let responseType: 'id_token' | 'id_token vp_token' | 'vp_token'
      if (idToken && payload.vp_token) {
        responseType = 'id_token vp_token'
      } else if (idToken) {
        responseType = 'id_token'
      } else if (payload.vp_token) {
        responseType = 'vp_token'
      }

      return sendJarmAuthRequest({
        authRequestParams: {
          response_uri: responseUri,
          response_mode: responseMode,
          response_type: responseType,
        },
        authResponseParams: { response: jwe },
      })
    }

    const authResponseAsURI = encodeJsonAsURI(payload, { arraysWithIndex: ['presentation_submission'] })
    return post(responseUri, authResponseAsURI, { contentType: ContentType.FORM_URL_ENCODED, exceptionOnHttpErrorStatus: true })
      .then((result: SIOPResonse<unknown>) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_SUCCESS, { correlationId, subject: response })
        return result.origResponse
      })
      .catch((error: Error) => {
        void this.emitEvent(AuthorizationEvents.ON_AUTH_RESPONSE_SENT_FAILED, { correlationId, subject: response, error })
        throw error
      })
  }

  /**
   * Create an Authentication Request Payload from a URI string
   *
   * @param encodedUri
   */
  public async parseAuthorizationRequestURI(encodedUri: string): Promise<ParsedAuthorizationRequestURI> {
    const { scheme, requestObjectJwt, authorizationRequestPayload, registrationMetadata } = await URI.parseAndResolve(encodedUri)

    return {
      encodedUri,
      encodingFormat: UrlEncodingFormat.FORM_URL_ENCODED,
      scheme: scheme,
      requestObjectJwt,
      authorizationRequestPayload,
      registration: registrationMetadata,
    }
  }

  private newAuthorizationResponseOpts(opts: {
    correlationId: string
    version?: SupportedVersion
    issuer?: IIssuerId | ResponseIss
    audience?: string
    presentationExchange?: PresentationExchangeResponseOpts
  }): AuthorizationResponseOpts {
    const version = opts.version ?? this._createResponseOptions.version
    let issuer = opts.issuer ?? this._createResponseOptions?.registration?.issuer
    if (version === SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1) {
      issuer = ResponseIss.JWT_VC_PRESENTATION_V1
    } else if (version === SupportedVersion.SIOPv2_ID1) {
      issuer = ResponseIss.SELF_ISSUED_V2
    }

    if (!issuer) {
      throw Error(`No issuer value present. Either use IDv1, JWT VC Presentation profile version, or provide a DID as issuer value`)
    }
    // We are taking the whole presentationExchange object from a certain location
    const presentationExchange = opts.presentationExchange ?? this._createResponseOptions.presentationExchange
    const responseURI = opts.audience ?? this._createResponseOptions.responseURI
    return {
      ...this._createResponseOptions,
      ...opts,
      ...(presentationExchange && { presentationExchange }),
      registration: { ...this._createResponseOptions?.registration, issuer },
      responseURI,
      responseURIType:
        this._createResponseOptions.responseURIType ?? (version < SupportedVersion.SIOPv2_D12_OID4VP_D18 && responseURI ? 'redirect_uri' : undefined),
    }
  }

  private newVerifyAuthorizationRequestOpts(requestOpts: { correlationId: string; verification?: Verification }): VerifyAuthorizationRequestOpts {
    const verification: VerifyAuthorizationRequestOpts = {
      ...this._verifyRequestOptions,
      verifyJwtCallback: this._verifyRequestOptions.verifyJwtCallback,
      ...requestOpts,
      verification: mergeVerificationOpts(this._verifyRequestOptions, requestOpts),
      correlationId: requestOpts.correlationId,
    }

    return verification
  }

  private async emitEvent(
    type: AuthorizationEvents,
    payload: {
      correlationId: string
      subject: AuthorizationRequest | AuthorizationResponse | string | URI
      error?: Error
    },
  ): Promise<void> {
    if (this._eventEmitter) {
      this._eventEmitter.emit(type, new AuthorizationEvent(payload))
    }
  }

  public addEventListener(register: RegisterEventListener) {
    if (!this._eventEmitter) {
      throw Error('Cannot add listeners if no event emitter is available')
    }
    const events = Array.isArray(register.event) ? register.event : [register.event]
    for (const event of events) {
      this._eventEmitter.addListener(event, register.listener)
    }
  }

  public static fromOpts(responseOpts: AuthorizationResponseOpts, verifyOpts: VerifyAuthorizationRequestOpts): OP {
    return new OP({ responseOpts, verifyOpts })
  }

  public static builder() {
    return new OPBuilder()
  }

  get createResponseOptions(): AuthorizationResponseOpts {
    return this._createResponseOptions
  }

  get verifyRequestOptions(): Partial<VerifyAuthorizationRequestOpts> {
    return this._verifyRequestOptions
  }
}
