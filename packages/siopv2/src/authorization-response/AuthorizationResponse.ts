import { ResponseType } from '@sphereon/oid4vc-common';

import { AuthorizationRequest, VerifyAuthorizationRequestOpts } from '../authorization-request';
import { assertValidVerifyAuthorizationRequestOpts } from '../authorization-request/Opts';
import { IDToken } from '../id-token';
import { AuthorizationResponsePayload, SIOPErrors, VerifiedAuthorizationRequest, VerifiedAuthorizationResponse } from '../types';

import { assertValidVerifiablePresentations, extractPresentationsFromAuthorizationResponse, verifyPresentations } from './OpenID4VP';
import { assertValidResponseOpts } from './Opts';
import { createResponsePayload } from './Payload';
import { AuthorizationResponseOpts, PresentationDefinitionWithLocation, VerifyAuthorizationResponseOpts } from './types';

export class AuthorizationResponse {
  private readonly _authorizationRequest?: AuthorizationRequest | undefined;
  // private _requestObject?: RequestObject | undefined
  private readonly _idToken?: IDToken;
  private readonly _payload: AuthorizationResponsePayload;

  private readonly _options?: AuthorizationResponseOpts;

  constructor({
    authorizationResponsePayload,
    idToken,
    responseOpts,
    authorizationRequest,
  }: {
    authorizationResponsePayload: AuthorizationResponsePayload;
    idToken?: IDToken;
    responseOpts?: AuthorizationResponseOpts;
    authorizationRequest?: AuthorizationRequest;
  }) {
    this._authorizationRequest = authorizationRequest;
    this._options = responseOpts;
    this._idToken = idToken;
    this._payload = authorizationResponsePayload;
  }

  /**
   * Creates a SIOP Response Object
   *
   * @param requestObject
   * @param responseOpts
   * @param verifyOpts
   */
  static async fromRequestObject(
    requestObject: string,
    responseOpts: AuthorizationResponseOpts,
    verifyOpts: VerifyAuthorizationRequestOpts,
  ): Promise<AuthorizationResponse> {
    assertValidVerifyAuthorizationRequestOpts(verifyOpts);
    assertValidResponseOpts(responseOpts);
    if (!requestObject || !requestObject.startsWith('ey')) {
      throw new Error(SIOPErrors.NO_JWT);
    }
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(requestObject);
    return AuthorizationResponse.fromAuthorizationRequest(authorizationRequest, responseOpts, verifyOpts);
  }

  static async fromPayload(
    authorizationResponsePayload: AuthorizationResponsePayload,
    responseOpts?: AuthorizationResponseOpts,
  ): Promise<AuthorizationResponse> {
    if (!authorizationResponsePayload) {
      throw new Error(SIOPErrors.NO_RESPONSE);
    }
    if (responseOpts) {
      assertValidResponseOpts(responseOpts);
    }
    const idToken = authorizationResponsePayload.id_token ? await IDToken.fromIDToken(authorizationResponsePayload.id_token) : undefined;
    return new AuthorizationResponse({ authorizationResponsePayload, idToken, responseOpts });
  }

  static async fromAuthorizationRequest(
    authorizationRequest: AuthorizationRequest,
    responseOpts: AuthorizationResponseOpts,
    verifyOpts: VerifyAuthorizationRequestOpts,
  ): Promise<AuthorizationResponse> {
    assertValidResponseOpts(responseOpts);
    if (!authorizationRequest) {
      throw new Error(SIOPErrors.NO_REQUEST);
    }
    const verifiedRequest = await authorizationRequest.verify(verifyOpts);
    return await AuthorizationResponse.fromVerifiedAuthorizationRequest(verifiedRequest, responseOpts, verifyOpts);
  }

  static async fromVerifiedAuthorizationRequest(
    verifiedAuthorizationRequest: VerifiedAuthorizationRequest,
    responseOpts: AuthorizationResponseOpts,
    verifyOpts: VerifyAuthorizationRequestOpts,
  ): Promise<AuthorizationResponse> {
    assertValidResponseOpts(responseOpts);
    if (!verifiedAuthorizationRequest) {
      throw new Error(SIOPErrors.NO_REQUEST);
    }

    const authorizationRequest = verifiedAuthorizationRequest.authorizationRequest;

    // const merged = verifiedAuthorizationRequest.authorizationRequest.requestObject, verifiedAuthorizationRequest.requestObject);
    // const presentationDefinitions = await PresentationExchange.findValidPresentationDefinitions(merged, await authorizationRequest.getSupportedVersion());
    const presentationDefinitions = JSON.parse(
      JSON.stringify(verifiedAuthorizationRequest.presentationDefinitions),
    ) as PresentationDefinitionWithLocation[];
    const wantsIdToken = await authorizationRequest.containsResponseType(ResponseType.ID_TOKEN);
    // const hasVpToken = await authorizationRequest.containsResponseType(ResponseType.VP_TOKEN);

    const idToken = wantsIdToken ? await IDToken.fromVerifiedAuthorizationRequest(verifiedAuthorizationRequest, responseOpts) : undefined;
    const idTokenPayload = idToken ? await idToken.payload() : undefined;
    const authorizationResponsePayload = await createResponsePayload(authorizationRequest, responseOpts, idTokenPayload);
    const response = new AuthorizationResponse({
      authorizationResponsePayload,
      idToken,
      responseOpts,
      authorizationRequest,
    });

    const wrappedPresentations = await extractPresentationsFromAuthorizationResponse(response, { hasher: verifyOpts.hasher });

    await assertValidVerifiablePresentations({
      presentationDefinitions,
      presentations: wrappedPresentations,
      verificationCallback: verifyOpts.verification.presentationVerificationCallback,
      opts: { ...responseOpts.presentationExchange, hasher: verifyOpts.hasher },
    });

    return response;
  }

  public async verify(verifyOpts: VerifyAuthorizationResponseOpts): Promise<VerifiedAuthorizationResponse> {
    // Merge payloads checks for inconsistencies in properties which are present in both the auth request and request object
    const merged = await this.mergedPayloads(true);
    if (verifyOpts.state && merged.state !== verifyOpts.state) {
      throw Error(SIOPErrors.BAD_STATE);
    }

    const verifiedIdToken = await this.idToken?.verify(verifyOpts);
    const oid4vp = await verifyPresentations(this, verifyOpts);

    return {
      authorizationResponse: this,
      verifyOpts,
      correlationId: verifyOpts.correlationId,
      ...(this.idToken && { idToken: verifiedIdToken }),
      ...(oid4vp && { oid4vpSubmission: oid4vp }),
    };
  }

  get authorizationRequest(): AuthorizationRequest | undefined {
    return this._authorizationRequest;
  }

  get payload(): AuthorizationResponsePayload {
    return this._payload;
  }

  get options(): AuthorizationResponseOpts | undefined {
    return this._options;
  }

  get idToken(): IDToken | undefined {
    return this._idToken;
  }

  public async getMergedProperty<T>(key: string, consistencyCheck?: boolean): Promise<T | undefined> {
    const merged = await this.mergedPayloads(consistencyCheck);
    return merged[key] as T;
  }

  public async mergedPayloads(consistencyCheck?: boolean): Promise<AuthorizationResponsePayload> {
    const idTokenPayload = await this.idToken?.payload();
    if (consistencyCheck !== false && idTokenPayload) {
      Object.entries(idTokenPayload).forEach((entry) => {
        if (typeof entry[0] === 'string' && this.payload[entry[0]] && this.payload[entry[0]] !== entry[1]) {
          throw Error(`Mismatch in Authorization Request and Request object value for ${entry[0]}`);
        }
      });
    }
    return { ...this.payload, ...idTokenPayload };
  }
}
