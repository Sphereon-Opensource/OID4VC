import {AccessTokenClient, AccessTokenRequest, AccessTokenResponse, AuthzFlowType, Builder, GrantTypes} from '../src';

import {UNIT_TEST_TIMEOUT} from './IT.spec';

describe('AccessTokenClient should', () => {
  it(
      'get Access Token without resulting in errors',
      async () => {
        const tokenRetriever: AccessTokenClient = new AccessTokenClient();

        const accessTokenIssuanceRequest: AccessTokenRequest = Builder<AccessTokenRequest>()
        .grant_type(GrantTypes.PRE_AUTHORIZED)
        .pre_authorized_code('20221013')
        .build();

        const accessTokenResponse: AccessTokenResponse = await tokenRetriever.acquireAccessToken(
            AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
            accessTokenIssuanceRequest,
            'https://sphereonjunit20221013.com/');

        expect(accessTokenResponse).toEqual(null);
      },
      UNIT_TEST_TIMEOUT
  );
});
