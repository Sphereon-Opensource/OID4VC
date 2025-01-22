import { JwtHeader, JwtIssuer, parseJWT } from '@sphereon/oid4vc-common'

import { ClaimPayloadCommonOpts, ClaimPayloadOptsVID1, CreateAuthorizationRequestOpts } from '../authorization-request'
import { assertValidAuthorizationRequestOpts } from '../authorization-request/Opts'
import { fetchByReferenceOrUseByValue, removeNullUndefined } from '../helpers'
import { AuthorizationRequestPayload, JwtIssuerWithContext, RequestObjectJwt, RequestObjectPayload, SIOPErrors } from '../types'

import { assertValidRequestObjectOpts } from './Opts'
import { assertValidRequestObjectPayload, createRequestObjectPayload } from './Payload'
import { RequestObjectOpts } from './types'

export class RequestObject {
  private payload: RequestObjectPayload
  private jwt?: RequestObjectJwt
  private readonly opts: RequestObjectOpts<ClaimPayloadCommonOpts | ClaimPayloadOptsVID1>

  private constructor(
    opts?: CreateAuthorizationRequestOpts | RequestObjectOpts<ClaimPayloadCommonOpts | ClaimPayloadOptsVID1>,
    payload?: RequestObjectPayload,
    jwt?: string,
  ) {
    this.opts = opts ? RequestObject.mergeOAuth2AndOpenIdProperties(opts) : undefined
    this.payload = payload
    this.jwt = jwt
  }

  /**
   * Create a request object that typically is used as a JWT on RP side, typically this method is called automatically when creating an Authorization Request, but you could use it directly!
   *
   * @param authorizationRequestOpts Request Object options to build a Request Object
   * @remarks This method is used to generate a SIOP request Object.
   * First it generates the request object payload, and then it a signed JWT can be accessed on request.
   *
   * Normally you will want to use the Authorization Request class. That class creates a URI that includes the JWT from this class in the URI
   * If you do use this class directly, you can call the `convertRequestObjectToURI` afterwards to get the URI.
   * Please note that the Authorization Request allows you to differentiate between OAuth2 and OpenID parameters that become
   * part of the URI and which become part of the Request Object. If you generate a URI based upon the result of this class,
   * the URI will be constructed based on the Request Object only!
   */
  public static async fromOpts(authorizationRequestOpts: CreateAuthorizationRequestOpts): Promise<RequestObject> {
    assertValidAuthorizationRequestOpts(authorizationRequestOpts)
    const createJwtCallback = authorizationRequestOpts.requestObject.createJwtCallback // We copy the signature separately as it can contain a function, which would be removed in the merge function below
    const jwtIssuer: JwtIssuer = authorizationRequestOpts.requestObject.jwtIssuer // We copy the signature separately as it can contain a function, which would be removed in the merge function below
    const requestObjectOpts: RequestObjectOpts<ClaimPayloadCommonOpts> = RequestObject.mergeOAuth2AndOpenIdProperties(authorizationRequestOpts)
    const mergedOpts = {
      ...authorizationRequestOpts,
      requestObject: { ...authorizationRequestOpts.requestObject, ...requestObjectOpts, createJwtCallback, jwtIssuer },
    }
    return new RequestObject(mergedOpts, await createRequestObjectPayload(mergedOpts))
  }

  public static async fromJwt(requestObjectJwt: RequestObjectJwt): Promise<RequestObject | undefined> {
    return requestObjectJwt ? new RequestObject(undefined, undefined, requestObjectJwt) : undefined
  }

  public static async fromPayload(
    requestObjectPayload: RequestObjectPayload,
    authorizationRequestOpts: CreateAuthorizationRequestOpts,
  ): Promise<RequestObject> {
    return new RequestObject(authorizationRequestOpts, requestObjectPayload)
  }

  public static async fromAuthorizationRequestPayload(payload: AuthorizationRequestPayload): Promise<RequestObject | undefined> {
    const requestObjectJwt =
      (payload.request ?? payload.request_uri) ? await fetchByReferenceOrUseByValue(payload.request_uri as string, payload.request, true) : undefined
    return requestObjectJwt ? await RequestObject.fromJwt(requestObjectJwt) : undefined
  }

  public async toJwt(): Promise<RequestObjectJwt | undefined> {
    if (!this.jwt) {
      if (!this.opts) {
        throw Error(SIOPErrors.BAD_PARAMS)
      } else if (!this.payload) {
        return undefined
      }
      this.removeRequestProperties()
      if (this.payload.registration_uri) {
        delete this.payload.registration
      }

      assertValidRequestObjectPayload(this.payload)

      const jwtIssuer: JwtIssuerWithContext = this.opts.jwtIssuer
        ? { ...this.opts.jwtIssuer, type: 'request-object' }
        : { method: 'custom', type: 'request-object' }

      if (jwtIssuer.method === 'custom') {
        this.jwt = await this.opts.createJwtCallback(jwtIssuer, { header: {}, payload: this.payload })
      } else if (jwtIssuer.method === 'did') {
        const did = jwtIssuer.didUrl.split('#')[0]
        this.payload.iss = this.payload.iss ?? did
        this.payload.sub = this.payload.sub ?? did
        this.payload.client_id = this.payload.client_id ?? did
        this.payload.client_id_scheme = 'did'

        const header = { kid: jwtIssuer.didUrl, alg: jwtIssuer.alg, typ: 'JWT' }
        this.jwt = await this.opts.createJwtCallback(jwtIssuer, { header, payload: this.payload })
      } else if (jwtIssuer.method === 'x5c') {
        this.payload.iss = jwtIssuer.issuer

        const header = { x5c: jwtIssuer.x5c, typ: 'JWT', alg: jwtIssuer.alg }
        this.jwt = await this.opts.createJwtCallback(jwtIssuer, { header, payload: this.payload })
      } else if (jwtIssuer.method === 'jwk') {
        if (!this.payload.client_id) {
          throw new Error('Please provide a client_id for the RP')
        }

        const header = { jwk: jwtIssuer.jwk, typ: 'JWT', alg: jwtIssuer.jwk.alg as string }
        this.jwt = await this.opts.createJwtCallback(jwtIssuer, { header, payload: this.payload })
      } else {
        throw new Error(`JwtIssuer method '${(jwtIssuer as JwtIssuer).method}' not implemented`)
      }
    }
    return this.jwt
  }

  public getPayload(): RequestObjectPayload | undefined {
    if (!this.payload) {
      if (!this.jwt) {
        return undefined
      }
      this.payload = removeNullUndefined(parseJWT<JwtHeader, RequestObjectPayload>(this.jwt).payload)
      this.removeRequestProperties()
      if (this.payload.registration_uri) {
        delete this.payload.registration
      } else if (this.payload.registration) {
        delete this.payload.registration_uri
      }
    }
    assertValidRequestObjectPayload(this.payload)
    return this.payload
  }

  public async assertValid(): Promise<void> {
    if (this.options) {
      assertValidRequestObjectOpts(this.options, false)
    }
    assertValidRequestObjectPayload(await this.getPayload())
  }

  public get options(): RequestObjectOpts<ClaimPayloadCommonOpts | ClaimPayloadOptsVID1> | undefined {
    return this.opts
  }

  private removeRequestProperties(): void {
    if (this.payload) {
      // https://openid.net/specs/openid-connect-core-1_0.html#RequestObject
      // request and request_uri parameters MUST NOT be included in Request Objects.
      delete this.payload.request
      delete this.payload.request_uri
    }
  }

  private static mergeOAuth2AndOpenIdProperties(
    opts: CreateAuthorizationRequestOpts | RequestObjectOpts<ClaimPayloadCommonOpts | ClaimPayloadOptsVID1>,
  ): RequestObjectOpts<ClaimPayloadCommonOpts | ClaimPayloadOptsVID1> {
    if (!opts) {
      throw Error(SIOPErrors.BAD_PARAMS)
    }
    const isAuthReq = opts['requestObject'] !== undefined
    const mergedOpts = JSON.parse(JSON.stringify(opts))
    const createJwtCallback = opts['requestObject']?.createJwtCallback
    if (createJwtCallback) {
      mergedOpts.requestObject.createJwtCallback = createJwtCallback
    }
    const jwtIssuer = opts['requestObject']?.jwtIssuer
    if (createJwtCallback) {
      mergedOpts.requestObject.jwtIssuer = jwtIssuer
    }
    delete mergedOpts?.request?.requestObject
    return isAuthReq ? mergedOpts.requestObject : mergedOpts
  }
}
