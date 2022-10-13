import { encodeJsonAsURI } from './functions';
import { AccessTokenRequest, AccessTokenResponse, AuthzFlowType, GrantTypes } from './types';
import { Builder } from './utils';

export class AccessTokenClient {
  const;
  PRE_AUTHORIZED_SCENARIO_MESSAGE = 'The grant type is set to be pre-authorized. ';

  private assertPreAuthorizedGrantType(grantType: string): void {
    if (GrantTypes.PRE_AUTHORIZED !== grantType) {
      throw new Error("grant type must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code'");
    }
  }

  private assertNumericPin(accessTokenRequest: AccessTokenRequest): void {
    if (accessTokenRequest.user_pin_required) {
      if (!(0 < accessTokenRequest.user_pin || accessTokenRequest.user_pin <= 99999999)) {
        throw new Error(
          this.PRE_AUTHORIZED_SCENARIO_MESSAGE + 'A valid pin consists of maximum 8 numeric characters (the numbers 0 - 9) must be present.'
        );
      }
    }
  }

  private assertNonEmptyPreAuthorizedCode(accessTokenRequest: AccessTokenRequest): void {
    if (!accessTokenRequest.pre_authorized_code) {
      throw new Error(
        this.PRE_AUTHORIZED_SCENARIO_MESSAGE + 'Pre-authorization must be proven by presenting the pre-authorized code. Code must be present.'
      );
    }
  }

  private assertNonEmptyClientId(accessTokenRequest: AccessTokenRequest): void {
    if (accessTokenRequest.client_id) {
      if (accessTokenRequest.client_id.length < 1) {
        throw new Error('The client Id must be present.');
      }
    }
  }

  private validate(authzFlowType: AuthzFlowType, accessTokenRequest: AccessTokenRequest): void {
    if (authzFlowType === AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW) {
      this.assertPreAuthorizedGrantType(accessTokenRequest.grant_type);
      this.assertNonEmptyPreAuthorizedCode(accessTokenRequest);
      this.assertNumericPin(accessTokenRequest);
      this.assertNonEmptyClientId(accessTokenRequest);
    }
  }

  private getEncodedAccessTokenURL(accessTokenRequest: AccessTokenRequest, issuerURL: string): URL {
    return new URL(issuerURL + '?' + encodeJsonAsURI(accessTokenRequest));
  }

  private async sendAuthCode(requestTokenURL: URL): Promise<AccessTokenResponse> {
    // TODO Implement
    return !requestTokenURL ? Builder<AccessTokenResponse>().build() : null;
  }

  public async acquireAccessToken(
    authFlowType: AuthzFlowType,
    accessTokenRequest: AccessTokenRequest,
    issuerURL: string
  ): Promise<AccessTokenResponse> {
    this.validate(authFlowType, accessTokenRequest);
    const requestTokenURL: URL = this.getEncodedAccessTokenURL(accessTokenRequest, issuerURL);
    return this.sendAuthCode(requestTokenURL);
  }
}
