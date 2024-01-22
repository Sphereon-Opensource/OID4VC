import { JWTVerifyOptions } from 'did-jwt';

import { PresentationDefinitionWithLocation } from '../authorization-response';
import { PresentationExchange } from '../authorization-response/PresentationExchange';
import { getAudience, getResolver, parseJWT, verifyDidJWT } from '../did';
import { fetchByReferenceOrUseByValue, removeNullUndefined } from '../helpers';
import { authorizationRequestVersionDiscovery } from '../helpers/SIOPSpecVersion';
import { RequestObject } from '../request-object';
import {
  AuthorizationRequestPayload,
  PassBy,
  RequestObjectJwt,
  RequestObjectPayload,
  ResponseURIType,
  RPRegistrationMetadataPayload,
  Schema,
  SIOPErrors,
  SupportedVersion,
  VerifiedAuthorizationRequest,
  VerifiedJWT,
} from '../types';

import { assertValidAuthorizationRequestOpts, assertValidVerifyAuthorizationRequestOpts } from './Opts';
import { assertValidRPRegistrationMedataPayload, checkWellknownDIDFromRequest, createAuthorizationRequestPayload } from './Payload';
import { URI } from './URI';
import { CreateAuthorizationRequestOpts, VerifyAuthorizationRequestOpts } from './types';

export class AuthorizationRequest {
  private readonly _requestObject?: RequestObject;
  private readonly _payload: AuthorizationRequestPayload;
  private readonly _options?: CreateAuthorizationRequestOpts;
  private _uri?: URI;

  private constructor(payload: AuthorizationRequestPayload, requestObject?: RequestObject, opts?: CreateAuthorizationRequestOpts, uri?: URI) {
    this._options = opts;
    this._payload = removeNullUndefined(payload);
    this._requestObject = requestObject;
    this._uri = uri;
  }

  public static async fromUriOrJwt(jwtOrUri?: string | URI): Promise<AuthorizationRequest> {
    if (!jwtOrUri) {
      throw Error(SIOPErrors.NO_REQUEST);
    }
    return typeof jwtOrUri === 'string' && jwtOrUri.startsWith('ey')
      ? await AuthorizationRequest.fromJwt(jwtOrUri)
      : await AuthorizationRequest.fromURI(jwtOrUri);
  }

  public static async fromPayload(payload: AuthorizationRequestPayload): Promise<AuthorizationRequest> {
    if (!payload) {
      throw Error(SIOPErrors.NO_REQUEST);
    }
    const requestObject = await RequestObject.fromAuthorizationRequestPayload(payload);
    return new AuthorizationRequest(payload, requestObject);
  }

  public static async fromOpts(opts: CreateAuthorizationRequestOpts, requestObject?: RequestObject): Promise<AuthorizationRequest> {
    // todo: response_uri/redirect_uri is not hooked up from opts!
    if (!opts || !opts.requestObject) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    assertValidAuthorizationRequestOpts(opts);

    const requestObjectArg =
      opts.requestObject.passBy !== PassBy.NONE ? (requestObject ? requestObject : await RequestObject.fromOpts(opts)) : undefined;
    const requestPayload = opts?.payload ? await createAuthorizationRequestPayload(opts, requestObjectArg) : undefined;
    if (!requestPayload) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    return new AuthorizationRequest(requestPayload, requestObjectArg, opts);
  }

  get payload(): AuthorizationRequestPayload {
    return this._payload;
  }

  get requestObject(): RequestObject | undefined {
    return this._requestObject;
  }

  get options(): CreateAuthorizationRequestOpts | undefined {
    return this._options;
  }

  public hasRequestObject(): boolean {
    return this.requestObject !== undefined;
  }

  public async getSupportedVersion() {
    if (this.options?.version) {
      return this.options.version;
    } else if (this._uri?.encodedUri?.startsWith(Schema.OPENID_VC) || this._uri?.scheme?.startsWith(Schema.OPENID_VC)) {
      return SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1;
    }

    return (await this.getSupportedVersionsFromPayload())[0];
  }

  public async getSupportedVersionsFromPayload(): Promise<SupportedVersion[]> {
    const mergedPayload = { ...this.payload, ...(await this.requestObject?.getPayload()) };
    return authorizationRequestVersionDiscovery(mergedPayload);
  }

  async uri(opts?: { requestPassBy?: PassBy }): Promise<URI> {
    if (!this._uri) {
      this._uri = await URI.fromAuthorizationRequest(this, { requestPassBy: opts?.requestPassBy ?? PassBy.REFERENCE });
    }
    return this._uri;
  }

  /**
   * Verifies a SIOP Request JWT on OP side
   *
   * @param opts
   */
  async verify(opts: VerifyAuthorizationRequestOpts): Promise<VerifiedAuthorizationRequest> {
    assertValidVerifyAuthorizationRequestOpts(opts);

    let requestObjectPayload: RequestObjectPayload | undefined = undefined;
    let verifiedJwt: VerifiedJWT | undefined = undefined;

    const jwt = await this.requestObjectJwt();
    if (jwt) {
      parseJWT(jwt);
      const resolver = getResolver(opts.verification.resolveOpts);
      const options: JWTVerifyOptions = {
        ...opts.verification?.resolveOpts?.jwtVerifyOpts,
        resolver,
        audience: getAudience(jwt),
      };

      verifiedJwt = await verifyDidJWT(jwt, resolver, options);
      if (!verifiedJwt || !verifiedJwt.payload) {
        throw Error(SIOPErrors.ERROR_VERIFYING_SIGNATURE);
      }
      requestObjectPayload = verifiedJwt.payload as RequestObjectPayload;

      if (this.hasRequestObject() && !this.payload.request_uri) {
        // Put back the request object as that won't be present yet
        this.payload.request = jwt;
      }
    }

    // AuthorizationRequest.assertValidRequestObject(origAuthenticationRequest);

    // We use the orig request for default values, but the JWT payload contains signed request object properties
    const mergedPayload = { ...this.payload, ...requestObjectPayload } as RequestObjectPayload;
    if (opts.state && mergedPayload.state !== opts.state) {
      throw new Error(`${SIOPErrors.BAD_STATE} payload: ${mergedPayload.state}, supplied: ${opts.state}`);
    } else if (opts.nonce && mergedPayload.nonce !== opts.nonce) {
      throw new Error(`${SIOPErrors.BAD_NONCE} payload: ${mergedPayload.nonce}, supplied: ${opts.nonce}`);
    }

    const registrationPropertyKey = mergedPayload['registration'] || mergedPayload['registration_uri'] ? 'registration' : 'client_metadata';
    let registrationMetadataPayload: RPRegistrationMetadataPayload | undefined = undefined;
    if (mergedPayload[registrationPropertyKey] || mergedPayload[`${registrationPropertyKey}_uri`]) {
      registrationMetadataPayload = await fetchByReferenceOrUseByValue(
        mergedPayload[`${registrationPropertyKey}_uri`],
        mergedPayload[registrationPropertyKey],
      );
      assertValidRPRegistrationMedataPayload(registrationMetadataPayload);
      // TODO: We need to do something with the metadata probably
    }
    // When the response_uri parameter is present, the redirect_uri Authorization Request parameter MUST NOT be present. If the redirect_uri Authorization Request parameter is present when the Response Mode is direct_post, the Wallet MUST return an invalid_request Authorization Response error.
    let responseURIType: ResponseURIType;
    let responseURI: string;
    if (mergedPayload.redirect_uri && mergedPayload.response_uri) {
      throw new Error(`${SIOPErrors.INVALID_REQUEST}, redirect_uri cannot be used together with response_uri`);
    } else if (mergedPayload.redirect_uri) {
      responseURIType = 'redirect_uri';
      responseURI = mergedPayload.redirect_uri;
    } else if (mergedPayload.response_uri) {
      responseURIType = 'response_uri';
      responseURI = mergedPayload.response_uri;
    } else if (mergedPayload.client_id_scheme === 'redirect_uri' && mergedPayload.client_id) {
      responseURIType = 'redirect_uri';
      responseURI = mergedPayload.client_id;
    } else {
      throw new Error(`${SIOPErrors.INVALID_REQUEST}, redirect_uri or response_uri is needed`);
    }
    if (!mergedPayload.scope) {
      throw new Error(`${SIOPErrors.INVALID_REQUEST}, Scope should be present`);
    }

    await checkWellknownDIDFromRequest(mergedPayload, opts);

    // TODO: we need to verify somewhere that if response_mode is direct_post, that the response_uri may be present,
    // BUT not both redirect_uri and response_uri. What is the best place to do this?

    const presentationDefinitions = await PresentationExchange.findValidPresentationDefinitions(mergedPayload, await this.getSupportedVersion());
    return {
      ...verifiedJwt,
      responseURIType,
      responseURI,
      clientIdScheme: mergedPayload.client_id_scheme,
      correlationId: opts.correlationId,
      authorizationRequest: this,
      verifyOpts: opts,
      presentationDefinitions,
      registrationMetadataPayload,
      requestObject: this.requestObject,
      authorizationRequestPayload: this.payload,
      versions: await this.getSupportedVersionsFromPayload(),
    };
  }

  static async verify(requestOrUri: string, verifyOpts: VerifyAuthorizationRequestOpts) {
    assertValidVerifyAuthorizationRequestOpts(verifyOpts);
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestOrUri);
    return await authorizationRequest.verify(verifyOpts);
  }

  public async requestObjectJwt(): Promise<RequestObjectJwt | undefined> {
    return await this.requestObject?.toJwt();
  }

  private static async fromJwt(jwt: string): Promise<AuthorizationRequest> {
    if (!jwt) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    const requestObject = await RequestObject.fromJwt(jwt);
    const payload: AuthorizationRequestPayload = { ...(requestObject && (await requestObject.getPayload())) } as AuthorizationRequestPayload;
    // Although this was a RequestObject we instantiate it as AuthzRequest and then copy in the JWT as the request Object
    payload.request = jwt;
    return new AuthorizationRequest({ ...payload }, requestObject);
  }

  private static async fromURI(uri: URI | string): Promise<AuthorizationRequest> {
    if (!uri) {
      throw Error(SIOPErrors.BAD_PARAMS);
    }
    const uriObject = typeof uri === 'string' ? await URI.fromUri(uri) : uri;
    const requestObject = await RequestObject.fromJwt(uriObject.requestObjectJwt);
    return new AuthorizationRequest(uriObject.authorizationRequestPayload, requestObject, undefined, uriObject);
  }

  public async containsResponseType(singleType: ResponseType | string): Promise<boolean> {
    const responseType: string | undefined = await this.getMergedProperty('response_type');
    return responseType?.includes(singleType) === true;
  }

  public async getMergedProperty<T>(key: string): Promise<T | undefined> {
    const merged = await this.mergedPayloads();
    return merged[key] as T;
  }

  public async mergedPayloads(): Promise<RequestObjectPayload> {
    return { ...this.payload, ...(this.requestObject && (await this.requestObject.getPayload())) } as RequestObjectPayload;
  }

  public async getPresentationDefinitions(version?: SupportedVersion): Promise<PresentationDefinitionWithLocation[] | undefined> {
    return await PresentationExchange.findValidPresentationDefinitions(await this.mergedPayloads(), version);
  }
}
