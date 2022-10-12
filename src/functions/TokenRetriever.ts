import {
  AccessTokenIssuanceRequest,
  AccessTokenIssuanceResponse,
  AuthorizationExchangeMetaData,
  AuthorizationRequest,
  ExchangeStep,
  GrantTypes,
} from '../types';
import { Builder } from '../utils';

export class TokenRetriever {
  const;
  PRE_AUTHORIZED_SCENARIO_MESSAGE = 'The grant type is set to be pre-authorized. ';

  private isGrantTypePreAuthorized(grantType: string): boolean {
    return GrantTypes['PRE-AUTHORIZED'] === grantType;
  }

  private assertPinIsValid(accessTokenIssuanceRequest: AccessTokenIssuanceRequest): void {
    if (accessTokenIssuanceRequest.user_pin_required) {
      if (!(0 < accessTokenIssuanceRequest.user_pin || accessTokenIssuanceRequest.user_pin <= 99999999)) {
        throw new Error(
          this.PRE_AUTHORIZED_SCENARIO_MESSAGE + 'A valid pin consists of maximum 8 numeric characters (the numbers 0 - 9) must be present.'
        );
      }
    }
  }

  private assertValidPreAuthorizedCode(accessTokenIssuanceRequest: AccessTokenIssuanceRequest): void {
    if (!accessTokenIssuanceRequest.pre_authorized_code) {
      throw new Error(
        this.PRE_AUTHORIZED_SCENARIO_MESSAGE + 'Pre-authorization must be proven by presenting the pre-authorized code. Code must be present.'
      );
    }
  }

  private assertRedirectURIISValid(authorizationRequest: AuthorizationRequest, accessTokenIssuanceRequest: AccessTokenIssuanceRequest) {
    if (authorizationRequest.redirect_uri) {
      if (!accessTokenIssuanceRequest.redirect_uri) {
        throw new Error('The redirect URI must be present as it is configured during authorization step.');
      }
    }
  }

  private validate(accessTokenIssuanceRequest: AccessTokenIssuanceRequest, authorizationExchangeMetaData: AuthorizationExchangeMetaData): void {
    if (this.isGrantTypePreAuthorized(accessTokenIssuanceRequest.grant_type)) {
      this.assertValidPreAuthorizedCode(accessTokenIssuanceRequest);
      this.assertPinIsValid(accessTokenIssuanceRequest);
    }

    const authorizationRequest = authorizationExchangeMetaData.exchanges.get(ExchangeStep.AUTHORIZATION).request as AuthorizationRequest;

    this.assertRedirectURIISValid(authorizationRequest, accessTokenIssuanceRequest);
  }

  private getEncodedAccessTokenURL(accessTokenIssuanceRequest: AccessTokenIssuanceRequest): URL {
    // TODO Implement
    return accessTokenIssuanceRequest ? new URL('https://sphereonDummyIssuer2022-10-11_00/token') : null;
  }

  private sendAccessToken(requestTokenURL: URL): AccessTokenIssuanceResponse {
    // TODO Implement
    return !requestTokenURL ? Builder<AccessTokenIssuanceResponse>().build() : null;
  }

  public getAccessToken(
    accessTokenIssuanceRequest: AccessTokenIssuanceRequest,
    authorizationExchangeMetaData: AuthorizationExchangeMetaData
  ): AccessTokenIssuanceResponse {
    this.validate(accessTokenIssuanceRequest, authorizationExchangeMetaData);
    const requestTokenURL: URL = this.getEncodedAccessTokenURL(accessTokenIssuanceRequest);
    return this.sendAccessToken(requestTokenURL);
  }
}
