import { encodeJsonAsURI, post } from './functions';
import { AccessTokenRequest, AccessTokenResponse, AuthzFlowType, GrantTypes } from './types';

export class AccessTokenClient {
  const;
  PRE_AUTHORIZED_SCENARIO_MESSAGE = 'The grant type is set to be pre-authorized. ';

  private assertPreAuthorizedGrantType(grantType: string): void {
    if (GrantTypes.PRE_AUTHORIZED !== grantType) {
      throw new Error("grant type must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code'");
    }
  }

  private assertNumericPin(accessTokenRequest: AccessTokenRequest, isPinRequired: boolean): void {
    if (isPinRequired) {
      if (!accessTokenRequest.user_pin || !(0 < accessTokenRequest.user_pin || accessTokenRequest.user_pin <= 99999999)) {
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
    if (!accessTokenRequest.client_id || accessTokenRequest.client_id.length < 1) {
      throw new Error('The client Id must be present.');
    }
  }

  private validate(authzFlowType: AuthzFlowType, accessTokenRequest: AccessTokenRequest, isPinRequired: boolean): void {
    if (authzFlowType === AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW) {
      this.assertPreAuthorizedGrantType(accessTokenRequest.grant_type);
      this.assertNonEmptyPreAuthorizedCode(accessTokenRequest);
      this.assertNumericPin(accessTokenRequest, isPinRequired);
      this.assertNonEmptyClientId(accessTokenRequest);
    }
  }

  private getEncodedAccessTokenURL(accessTokenRequest: AccessTokenRequest, issuerURL: string): URL {
    return new URL(issuerURL + '?' + encodeJsonAsURI(accessTokenRequest));
  }

  private async sendAuthCode(tokenRequestURL: URL, accessTokenRequest: AccessTokenRequest): Promise<AccessTokenResponse> {
    const response = await post(tokenRequestURL.toString(), accessTokenRequest);
    return (await response).json() as AccessTokenResponse;
  }

  public async acquireAccessToken(
    authFlowType: AuthzFlowType,
    accessTokenRequest: AccessTokenRequest,
    issuerURL: string,
    isPinRequired?: boolean
  ): Promise<AccessTokenResponse> {
    this.validate(authFlowType, accessTokenRequest, isPinRequired);
    const requestTokenURL: URL = this.getEncodedAccessTokenURL(accessTokenRequest, issuerURL);
    return this.sendAuthCode(requestTokenURL, accessTokenRequest);
  }
}
