import nock from 'nock';

import { AccessTokenClient } from '../lib';
import { AccessTokenRequest, AccessTokenResponse, GrantTypes, OpenIDResponse  } from '@sphereon/openid4vci-common'

import { UNIT_TEST_TIMEOUT } from './IT.spec';
import { INITIATION_TEST } from './MetadataMocks';

const MOCK_URL = 'https://sphereonjunit20221013.com/';

describe('AccessTokenClient should', () => {
  beforeEach(() => {
    nock.cleanAll();
  });
  it(
    'get Access Token without resulting in errors',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        'pre-authorized_code': '20221013',
        client_id: 'sphereon',
      } as AccessTokenRequest;

      const body: AccessTokenResponse = {
        access_token: 'ey6546.546654.64565',
        authorization_pending: false,
        c_nonce: 'c_nonce2022101300',
        c_nonce_expires_in: 2022101300,
        interval: 2022101300,
        token_type: 'Bearer',
      };
      nock(MOCK_URL).post(/.*/).reply(200, JSON.stringify(body));

      const accessTokenResponse: OpenIDResponse<AccessTokenResponse> = await accessTokenClient.acquireAccessTokenUsingRequest({
        accessTokenRequest,
        asOpts: { as: MOCK_URL },
      });

      expect(accessTokenResponse.successBody).toEqual(body);
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get error',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenRequest: AccessTokenRequest = {
        grant_type: GrantTypes.AUTHORIZATION_CODE,
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, '');

      await expect(
        accessTokenClient.acquireAccessTokenUsingRequest({
          accessTokenRequest,
          asOpts: { as: MOCK_URL },
        })
      ).rejects.toThrow('Only pre-authorized-code flow is supported');
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get error for incorrect code',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        'pre-authorized_code': '',
        user_pin: '1.0',
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, {});

      await expect(
        accessTokenClient.acquireAccessTokenUsingRequest({
          accessTokenRequest,
          asOpts: { as: MOCK_URL },
        })
      ).rejects.toThrow('Pre-authorization must be proven by presenting the pre-authorized code. Code must be present.');
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get error for incorrect pin',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        'pre-authorized_code': '20221013',
        user_pin: null,
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, {});

      await expect(
        accessTokenClient.acquireAccessTokenUsingRequest({
          accessTokenRequest,
          isPinRequired: true,
          asOpts: { as: MOCK_URL },
        })
      ).rejects.toThrow('A valid pin consisting of maximal 8 numeric characters must be present.');
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get error for incorrectly long pin',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        'pre-authorized_code': '20221013',
        client_id: 'sphereon.com',
        user_pin: '123456789',
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, {});

      await expect(
        accessTokenClient.acquireAccessTokenUsingRequest({
          accessTokenRequest,
          isPinRequired: true,
          asOpts: { as: MOCK_URL },
        })
      ).rejects.toThrow(Error('A valid pin consisting of maximal 8 numeric characters must be present.'));
    },
    UNIT_TEST_TIMEOUT
  );

  it(
    'get success for correct length of pin',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        'pre-authorized_code': '20221013',
        client_id: 'sphereon.com',
        user_pin: '12345678',
      } as AccessTokenRequest;

      const body: AccessTokenResponse = {
        access_token: 'ey6546.546654.64565',
        authorization_pending: false,
        c_nonce: 'c_nonce2022101300',
        c_nonce_expires_in: 2022101300,
        interval: 2022101300,
        token_type: 'Bearer',
      };
      nock(MOCK_URL).post(/.*/).reply(200, body);

      const response = await accessTokenClient.acquireAccessTokenUsingRequest({
        accessTokenRequest,
        isPinRequired: true,
        asOpts: { as: MOCK_URL },
      });
      expect(response.successBody).toEqual(body);
    },
    UNIT_TEST_TIMEOUT
  );

  it('get error for using a pin when not requested', async () => {
    const accessTokenClient: AccessTokenClient = new AccessTokenClient();

    nock(MOCK_URL).post(/.*/).reply(200, {});

    await expect(() =>
      accessTokenClient.acquireAccessTokenUsingIssuanceInitiation({
        issuanceInitiation: INITIATION_TEST,
        pin: '1234',
      })
    ).rejects.toThrow(Error('Cannot set a pin, when the pin is not required.'));
  });

  it('get error for unsupported flow type', async () => {
    const accessTokenClient: AccessTokenClient = new AccessTokenClient();

    await expect(accessTokenClient.acquireAccessTokenUsingRequest({ accessTokenRequest: {} as never })).rejects.toThrow(
      Error('Only pre-authorized-code flow is supported')
    );
  });

  it('get error if no as, issuer and metadata values are present', async () => {
    await expect(() =>
      AccessTokenClient.determineTokenURL({
        asOpts: undefined,
        issuerOpts: undefined,
        metadata: undefined,
      })
    ).toThrow(Error('Cannot determine token URL if no issuer, metadata and no Authorization Server values are present'));
  });
});
