import nock from "nock";

import {AccessTokenClient, AccessTokenRequest, AccessTokenResponse, AuthzFlowType, GrantTypes} from '../src';

import {UNIT_TEST_TIMEOUT} from './IT.spec';

describe('AccessTokenClient should', () => {
  it(
      'get Access Token without resulting in errors',
      async () => {
        const tokenRetriever: AccessTokenClient = new AccessTokenClient();

        const accessTokenIssuanceRequest: AccessTokenRequest = {
          grant_type: GrantTypes.PRE_AUTHORIZED,
          pre_authorized_code: '20221013'
        } as AccessTokenRequest;

        const body: AccessTokenResponse = {
          access_token: 20221013,
          authorization_pending: false,
          c_nonce: 'c_nonce2022101300',
          c_nonce_expires_in: 2022101300,
          interval: 2022101300,
          token_type: 'Bearer'
        };
        nock('https://sphereonjunit20221013.com/').post(/.*/).reply(200, JSON.stringify(body));

        const accessTokenResponse: AccessTokenResponse = await tokenRetriever.acquireAccessToken(
            AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
            accessTokenIssuanceRequest,
            'https://sphereonjunit20221013.com/');

        expect(accessTokenResponse).toEqual(body);
      },
      UNIT_TEST_TIMEOUT
  );
});
