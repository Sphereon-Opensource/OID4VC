import { ObjectUtils } from '@sphereon/ssi-types';

import { convertJsonToURI, post } from './functions';
import { AccessTokenRequest, AccessTokenResponse, ErrorResponse, GrantTypes, IssuanceInitiationRequestPayload } from './types';

interface AccessTokenRequestOpts {
  pin?: number;
  client_id?: string;
}

export class AccessTokenClient {
  private _clientId?: string;
  private _authorizationServerUrl?: string;

  public async acquireAccessTokenUsingIssuanceInitiationRequest(
    issuanceInitiationRequest: IssuanceInitiationRequestPayload,
    opts?: { authorizationServerUrl?: string; isPinRequired?: boolean; pin?: number }
  ): Promise<AccessTokenResponse | ErrorResponse> {
    // We get the auth server from the options, or else the issuer is assumed. This is different from the other acquire method, where the authorization server is mandatory
    const authorizationServerUrl = opts?.authorizationServerUrl
      ? opts.authorizationServerUrl
      : this._authorizationServerUrl
      ? this._authorizationServerUrl
      : issuanceInitiationRequest.issuer;

    return await this.acquireAccessTokenUsingRequest(
      await this.createAccessTokenRequest(issuanceInitiationRequest, {
        authorizationServerUrl: this.determineAuthorizationServerUrl(authorizationServerUrl),
        ...opts,
      })
    );
  }

  public async acquireAccessTokenUsingRequest(
    accessTokenRequest: AccessTokenRequest,
    opts?: { isPinRequired?: boolean; authorizationServerUrl?: string }
  ): Promise<AccessTokenResponse | ErrorResponse> {
    this.validate(accessTokenRequest, opts?.isPinRequired);
    const requestTokenURL = convertJsonToURI(accessTokenRequest, {
      baseUrl: this.determineAuthorizationServerUrl(opts?.authorizationServerUrl),
    });
    return this.sendAuthCode(requestTokenURL, accessTokenRequest);
  }

  public async createAccessTokenRequest(
    issuanceInitiationRequest: IssuanceInitiationRequestPayload,
    opts?: AccessTokenRequestOpts
  ): Promise<AccessTokenRequest> {
    const request: Partial<AccessTokenRequest> = {
      client_id: opts?.client_id ? opts.client_id : this._clientId,
    };
    if (issuanceInitiationRequest.user_pin_required) {
      this.assertNumericPin(true, opts.pin);
      request.user_pin = opts.pin;
    }
    if (issuanceInitiationRequest.pre_authorized_code) {
      request.grant_type = GrantTypes.PRE_AUTHORIZED_CODE;
      request.pre_authorized_code = issuanceInitiationRequest.pre_authorized_code;
    }
    if (issuanceInitiationRequest.op_state) {
      if (issuanceInitiationRequest.pre_authorized_code) {
        throw new Error('Cannot have both a pre_authorized_code and a op_state in the same initiation request');
      }
      request.grant_type = GrantTypes.AUTHORIZATION_CODE;
      this.throwNotSupportedFlow();
    }

    return request as AccessTokenRequest;
  }

  private assertPreAuthorizedGrantType(grantType: GrantTypes): void {
    if (GrantTypes.PRE_AUTHORIZED_CODE !== grantType) {
      throw new Error("grant type must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code'");
    }
  }

  private assertNumericPin(isPinRequired?: boolean, pin?: number): void {
    if (isPinRequired) {
      if (!pin || pin < 0 || 99999999 < pin) {
        throw new Error('A valid pin consisting of maximal 8 numeric characters must be present.');
      }
    } else if (pin) {
      throw new Error('Cannot set a pin, when the pin is not required.');
    }
  }

  private assertNonEmptyPreAuthorizedCode(accessTokenRequest: AccessTokenRequest): void {
    if (!accessTokenRequest.pre_authorized_code) {
      throw new Error('Pre-authorization must be proven by presenting the pre-authorized code. Code must be present.');
    }
  }

  private assertNonEmptyClientId(accessTokenRequest: AccessTokenRequest): void {
    if (!accessTokenRequest.client_id || accessTokenRequest.client_id.length < 1) {
      throw new Error('The client Id must be present.');
    }
  }

  private validate(accessTokenRequest: AccessTokenRequest, isPinRequired?: boolean): void {
    if (accessTokenRequest.grant_type === GrantTypes.PRE_AUTHORIZED_CODE) {
      this.assertPreAuthorizedGrantType(accessTokenRequest.grant_type);
      this.assertNonEmptyPreAuthorizedCode(accessTokenRequest);
      this.assertNumericPin(isPinRequired, accessTokenRequest.user_pin);
      this.assertNonEmptyClientId(accessTokenRequest);
    } else {
      this.throwNotSupportedFlow();
    }
  }

  private async sendAuthCode(requestTokenURL: string, accessTokenRequest: AccessTokenRequest): Promise<AccessTokenResponse | ErrorResponse> {
    const response = await post(requestTokenURL, accessTokenRequest);
    return await response.json();
  }

  private determineAuthorizationServerUrl(authorizationServerUrl?: string): string {
    const url = authorizationServerUrl ? authorizationServerUrl : this._authorizationServerUrl;
    if (!url || !ObjectUtils.isString(url)) {
      throw new Error('No authorization server URL present. Cannot acquire access token');
    }
    return url;
  }

  private throwNotSupportedFlow(): void {
    throw new Error('Only pre-authorized-code flow is supported');
  }
}
