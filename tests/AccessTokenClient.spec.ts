import nock from 'nock';

import { AccessTokenClient, AccessTokenRequest, AccessTokenResponse, GrantTypes } from '../lib';

import { UNIT_TEST_TIMEOUT } from './IT.spec';

const MOCK_URL = 'https://sphereonjunit20221013.com/';

describe('AccessTokenClient should', () => {
  it(
    'get Access Token without resulting in errors',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenIssuanceRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        pre_authorized_code: '20221013',
        client_id: 'sphereon',
      } as AccessTokenRequest;

      const body: AccessTokenResponse = {
        access_token: 20221013,
        authorization_pending: false,
        c_nonce: 'c_nonce2022101300',
        c_nonce_expires_in: 2022101300,
        interval: 2022101300,
        token_type: 'Bearer',
      };
      nock(MOCK_URL).post(/.*/).reply(200, JSON.stringify(body));

      const accessTokenResponse: AccessTokenResponse = (await accessTokenClient.acquireAccessTokenUsingRequest(accessTokenIssuanceRequest, {
        asOpts: { as: MOCK_URL },
      })) as AccessTokenResponse;

      expect(accessTokenResponse).toEqual(body);
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get error',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenIssuanceRequest: AccessTokenRequest = {
        grant_type: GrantTypes.AUTHORIZATION_CODE,
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, '');

      await expect(accessTokenClient.acquireAccessTokenUsingRequest(accessTokenIssuanceRequest, { asOpts: { as: MOCK_URL } })).rejects.toThrow(
        'Only pre-authorized-code flow is supported'
      );
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get error for incorrect code',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenIssuanceRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        pre_authorized_code: '',
        user_pin: 1.0,
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, {});

      await expect(accessTokenClient.acquireAccessTokenUsingRequest(accessTokenIssuanceRequest, { asOpts: { as: MOCK_URL } })).rejects.toThrow(
        'Pre-authorization must be proven by presenting the pre-authorized code. Code must be present.'
      );
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get error for incorrect pin',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenIssuanceRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        pre_authorized_code: '20221013',
        user_pin: null,
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, {});

      await expect(
        accessTokenClient.acquireAccessTokenUsingRequest(accessTokenIssuanceRequest, { isPinRequired: true, asOpts: { as: MOCK_URL } })
      ).rejects.toThrow('A valid pin consisting of maximal 8 numeric characters must be present.');
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get error for incorrect client id',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenIssuanceRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        pre_authorized_code: '20221013',
        user_pin: 20221013,
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, {});

      await expect(
        accessTokenClient.acquireAccessTokenUsingRequest(accessTokenIssuanceRequest, { isPinRequired: true, asOpts: { as: MOCK_URL } })
      ).rejects.toThrow('The client Id must be present.');
    },
    UNIT_TEST_TIMEOUT
  );
  it(
    'get error for incorrectly long pin',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenIssuanceRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        pre_authorized_code: '20221013',
        client_id: 'spheroen.com',
        user_pin: 123456789,
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, {});

      await expect(
        accessTokenClient.acquireAccessTokenUsingRequest(accessTokenIssuanceRequest, { isPinRequired: true, asOpts: { as: MOCK_URL } })
      ).rejects.toThrow(Error('A valid pin consisting of maximal 8 numeric characters must be present.'));
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get error for unsupported flow type',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      await expect(accessTokenClient.acquireAccessTokenUsingRequest({} as AccessTokenRequest, {})).rejects.toThrow(
        Error('Only pre-authorized-code flow is supported')
      );
    },
    UNIT_TEST_TIMEOUT
  );
});
