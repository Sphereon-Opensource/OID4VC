import nock from "nock";

import {AccessTokenClient, AccessTokenRequest, AccessTokenResponse, AuthzFlowType, GrantTypes} from '../src';

import {UNIT_TEST_TIMEOUT} from './IT.spec';

describe('AccessTokenClient should', () => {
  it(
      'get Access Token without resulting in errors',
      async () => {
        const accessTokenClient: AccessTokenClient = new AccessTokenClient();

        const accessTokenIssuanceRequest: AccessTokenRequest = {
          grant_type: GrantTypes.PRE_AUTHORIZED,
          pre_authorized_code: '20221013',
          client_id: 'sphereon'
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

        const accessTokenResponse: AccessTokenResponse = await accessTokenClient.acquireAccessToken(
            AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
            accessTokenIssuanceRequest,
            'https://sphereonjunit20221013.com/');

        expect(accessTokenResponse).toEqual(body);
      },
      UNIT_TEST_TIMEOUT
  );

  it(
      'get error',
      async () => {
        const accessTokenClient: AccessTokenClient = new AccessTokenClient();

        const accessTokenIssuanceRequest: AccessTokenRequest = {
          grant_type: GrantTypes.AUTHORIZATION_CODE
        } as AccessTokenRequest;


        nock('https://sphereonjunit20221013.com/').post(/.*/).reply(200, '');

        await expect(
            accessTokenClient.acquireAccessToken(
            AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
            accessTokenIssuanceRequest,
            'https://sphereonjunit20221013.com/')
        ).rejects.toThrow('grant type must be \'urn:ietf:params:oauth:grant-type:pre-authorized_code\'');
      },
      UNIT_TEST_TIMEOUT
  );

  it(
      'get error for incorrect code',
      async () => {

        const accessTokenClient: AccessTokenClient = new AccessTokenClient();

        const accessTokenIssuanceRequest: AccessTokenRequest = {
          grant_type: GrantTypes.PRE_AUTHORIZED,
          pre_authorized_code: '',
          user_pin: 1.0
        } as AccessTokenRequest;

        nock('https://sphereonjunit20221013.com/').post(/.*/).reply(200, {});

        await expect(
            accessTokenClient.acquireAccessToken(
              AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
              accessTokenIssuanceRequest,
              'https://sphereonjunit20221013.com/',
              true)
        ).rejects.toThrow('The grant type is set to be pre-authorized. Pre-authorization must be proven by presenting the pre-authorized code. Code must be present.');
      },
      UNIT_TEST_TIMEOUT
  );

  it(
      'get error for incorrect pin',
      async () => {

        const accessTokenClient: AccessTokenClient = new AccessTokenClient();

        const accessTokenIssuanceRequest: AccessTokenRequest = {
          grant_type: GrantTypes.PRE_AUTHORIZED,
          pre_authorized_code: '20221013',
          user_pin: null
        } as AccessTokenRequest;

        nock('https://sphereonjunit20221013.com/').post(/.*/).reply(200, {});

        await expect(
            accessTokenClient.acquireAccessToken(
              AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
              accessTokenIssuanceRequest,
              'https://sphereonjunit20221013.com/',
              true)
        ).rejects.toThrow('The grant type is set to be pre-authorized. A valid pin consists of maximum 8 numeric characters (the numbers 0 - 9) must be present.');
      },
      UNIT_TEST_TIMEOUT
  );

  it(
      'get error for incorrect client id',
      async () => {

        const accessTokenClient: AccessTokenClient = new AccessTokenClient();

        const accessTokenIssuanceRequest: AccessTokenRequest = {
          grant_type: GrantTypes.PRE_AUTHORIZED,
          pre_authorized_code: '20221013',
          user_pin: 20221013
        } as AccessTokenRequest;

        nock('https://sphereonjunit20221013.com/').post(/.*/).reply(200, {});

        await expect(
            accessTokenClient.acquireAccessToken(
              AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
              accessTokenIssuanceRequest,
              'https://sphereonjunit20221013.com/',
              true)
        ).rejects.toThrow('The client Id must be present.');
      },
      UNIT_TEST_TIMEOUT
  );
  it(
      'get error for incorrectly long pin',
      async () => {

        const accessTokenClient: AccessTokenClient = new AccessTokenClient();

        const accessTokenIssuanceRequest: AccessTokenRequest = {
          grant_type: GrantTypes.PRE_AUTHORIZED,
          pre_authorized_code: '20221013',
          client_id: 'spheroen.com',
          user_pin: 123456789
        } as AccessTokenRequest;

        nock('https://sphereonjunit20221013.com/').post(/.*/).reply(200, {});

        await expect(
            accessTokenClient.acquireAccessToken(
            AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
            accessTokenIssuanceRequest,
            'https://sphereonjunit20221013.com/',
            true)
        ).rejects.toThrow(
            Error('The grant type is set to be pre-authorized. A valid pin consists of maximum 8 numeric characters (the numbers 0 - 9) must be present.')
        );
      },
      UNIT_TEST_TIMEOUT
  );

  it(
      'get error for unsupported flow type',
      async () => {

        const accessTokenClient: AccessTokenClient = new AccessTokenClient();

        await expect(
            accessTokenClient.acquireAccessToken(
                AuthzFlowType.AUTHORIZATION_CODE_FLOW,
                {} as AccessTokenRequest,
                '',
                false)
        ).rejects.toThrow(
            Error('Non-pre-authorized flow is not yet supported.')
        );
      },
      UNIT_TEST_TIMEOUT
  );

});
