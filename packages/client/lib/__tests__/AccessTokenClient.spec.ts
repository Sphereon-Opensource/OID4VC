import { AccessTokenRequest, AccessTokenResponse, GrantTypes, OpenIDResponse, WellKnownEndpoints } from '@sphereon/oid4vci-common';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock';

import { AccessTokenClient } from '../AccessTokenClient';

import { UNIT_TEST_TIMEOUT } from './IT.spec';
import { INITIATION_TEST } from './MetadataMocks';

const MOCK_URL = 'https://sphereonjunit20221013.com/';

describe('AccessTokenClient should', () => {
  beforeEach(() => {
    nock.cleanAll();
    nock(MOCK_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, {});
    nock(MOCK_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {});
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it(
    'get Access Token for with pre-authorized code without resulting in errors',
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
    UNIT_TEST_TIMEOUT,
  );

  it(
    'get Access Token for authorization code without resulting in errors',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenRequest: AccessTokenRequest = {
        client_id: 'test-client',
        code_verifier: 'F0Y2OGARX2ppIERYdSVuLCV3Zi95Ci5yWzAYNU8QQC0',
        code: '9mq3kwIuNZ88czRjJ2-UDxtaNXulOfxHSXo-kM01MLV',
        redirect_uri: 'http://test.com/cb',
        grant_type: GrantTypes.AUTHORIZATION_CODE,
      } as AccessTokenRequest;

      const body: AccessTokenResponse = {
        access_token: '6W-kZopGNBq8e-5KvnGf2u0p0iGSxWZ7jIGV86nO1Dn',
        expires_in: 3600,
        scope: 'TestCredential',
        token_type: 'Bearer',
      };
      nock(MOCK_URL).post(/.*/).reply(200, JSON.stringify(body));

      const accessTokenResponse: OpenIDResponse<AccessTokenResponse> = await accessTokenClient.acquireAccessTokenUsingRequest({
        accessTokenRequest,
        asOpts: { as: MOCK_URL },
      });

      expect(accessTokenResponse.successBody).toEqual(body);
    },
    UNIT_TEST_TIMEOUT,
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
        }),
      ).rejects.toThrow('Pre-authorization must be proven by presenting the pre-authorized code. Code must be present.');
    },
    UNIT_TEST_TIMEOUT,
  );

  it(
    'get error for incorrect pin',
    async () => {
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();

      const accessTokenRequest: AccessTokenRequest = {
        grant_type: GrantTypes.PRE_AUTHORIZED_CODE,
        'pre-authorized_code': '20221013',
      } as AccessTokenRequest;

      nock(MOCK_URL).post(/.*/).reply(200, {});

      await expect(
        accessTokenClient.acquireAccessTokenUsingRequest({
          accessTokenRequest,
          isPinRequired: true,
          asOpts: { as: MOCK_URL },
        }),
      ).rejects.toThrow('A valid pin consisting of maximal 8 numeric characters must be present.');
    },
    UNIT_TEST_TIMEOUT,
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
        }),
      ).rejects.toThrow(Error('A valid pin consisting of maximal 8 numeric characters must be present.'));
    },
    UNIT_TEST_TIMEOUT,
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
    UNIT_TEST_TIMEOUT,
  );

  it('get error for using a pin when not requested', async () => {
    const accessTokenClient: AccessTokenClient = new AccessTokenClient();

    nock(MOCK_URL).post(/.*/).reply(200, {});

    await expect(() =>
      accessTokenClient.acquireAccessToken({
        credentialOffer: INITIATION_TEST,
        pin: '1234',
      }),
    ).rejects.toThrow(Error('Cannot set a pin, when the pin is not required.'));
  });

  it('get error if no as, issuer and metadata values are present', async () => {
    await expect(() =>
      AccessTokenClient.determineTokenURL({
        asOpts: undefined,
        issuerOpts: undefined,
        metadata: undefined,
      }),
    ).toThrow(Error('Cannot determine token URL if no issuer, metadata and no Authorization Server values are present'));
  });
});
