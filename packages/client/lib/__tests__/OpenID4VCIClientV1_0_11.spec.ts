import { CodeChallengeMethod, WellKnownEndpoints } from '@sphereon/oid4vci-common';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock';

import { OpenID4VCIClientV1_0_11 } from '../OpenID4VCIClientV1_0_11';

const MOCK_URL = 'https://server.example.com/';

describe('OpenID4VCIClientV1_0_11 should', () => {
  let client: OpenID4VCIClientV1_0_11;

  beforeEach(async () => {
    nock(MOCK_URL).get(/.*/).reply(200, {});
    nock(MOCK_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, {});
    nock(MOCK_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {});
    client = await OpenID4VCIClientV1_0_11.fromURI({
      clientId: 'test-client',
      uri: 'openid-initiate-issuance://?issuer=https://server.example.com&credential_type=TestCredential',
      createAuthorizationRequestURL: false,
    });
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it('should successfully construct an authorization request url', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._state.endpointMetadata?.credentialIssuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;
    const url = await client.createAuthorizationRequestUrl({
      authorizationRequest: {
        scope: 'openid TestCredential',
        redirectUri: 'http://localhost:8881/cb',
      },
    });

    const urlSearchParams = new URLSearchParams(url.split('?')[1]);
    const scope = urlSearchParams.get('scope')?.split(' ');

    expect(scope?.[0]).toBe('openid');
  });
  it('throw an error if authorization endpoint is not set in server metadata', async () => {
    await expect(
      client.createAuthorizationRequestUrl({
        authorizationRequest: {
          scope: 'openid TestCredential',
          redirectUri: 'http://localhost:8881/cb',
        },
      }),
    ).rejects.toThrow(Error('Server metadata does not contain authorization endpoint'));
  });
  it("injects 'openid' as the first scope if not provided", async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._state.endpointMetadata?.credentialIssuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    const url = await client.createAuthorizationRequestUrl({
      pkce: {
        codeChallengeMethod: CodeChallengeMethod.S256,
        codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
      },
      authorizationRequest: {
        scope: 'TestCredential',
        redirectUri: 'http://localhost:8881/cb',
      },
    });

    const urlSearchParams = new URLSearchParams(url.split('?')[1]);
    const scope = urlSearchParams.get('scope')?.split(' ');

    expect(scope?.[0]).toBe('openid');
  });
  it('throw an error if no scope and no authorization_details is provided', async () => {
    nock(MOCK_URL).get(/.*/).reply(200, {});
    nock(MOCK_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, {});
    nock(MOCK_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(200, {});
    // Use a client with issuer only to trigger the error
    client = await OpenID4VCIClientV1_0_11.fromCredentialIssuer({
      credentialIssuer: MOCK_URL,
      createAuthorizationRequestURL: false,
      retrieveServerMetadata: false,
    });

    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._state.endpointMetadata = {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      credentialIssuerMetadata: {
        authorization_endpoint: `${MOCK_URL}v1/auth/authorize`,
        token_endpoint: `${MOCK_URL}/token`,
      },
    };
    // client._state.endpointMetadata.credentialIssuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    await expect(
      client.createAuthorizationRequestUrl({
        pkce: {
          codeChallengeMethod: CodeChallengeMethod.S256,
          codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        },
        authorizationRequest: {
          redirectUri: 'http://localhost:8881/cb',
        },
      }),
    ).rejects.toThrow(Error('Please provide a scope or authorization_details if no credential offer is present'));
  });
  it('create an authorization request url with authorization_details array property', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._state.endpointMetadata?.credentialIssuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    await expect(
      client.createAuthorizationRequestUrl({
        pkce: {
          codeChallengeMethod: CodeChallengeMethod.S256,
          codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        },
        authorizationRequest: {
          authorizationDetails: [
            {
              type: 'openid_credential',
              format: 'ldp_vc',
              credential_definition: {
                '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
                types: ['VerifiableCredential', 'UniversityDegreeCredential'],
              },
            },
            {
              type: 'openid_credential',
              // eslint-disable-next-line @typescript-eslint/ban-ts-comment
              // @ts-ignore
              format: 'mso_mdoc',
              doctype: 'org.iso.18013.5.1.mDL',
            },
          ],
          redirectUri: 'http://localhost:8881/cb',
        },
      }),
    ).resolves.toEqual(
      'https://server.example.com/v1/auth/authorize?response_type=code&code_challenge_method=S256&code_challenge=mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs&authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22ldp_vc%22%2C%22credential_definition%22%3A%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fexamples%2Fv1%22%5D%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%2C%22locations%22%3A%5B%22https%3A%2F%2Fserver%2Eexample%2Ecom%22%5D%7D%2C%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22mso_mdoc%22%2C%22doctype%22%3A%22org%2Eiso%2E18013%2E5%2E1%2EmDL%22%2C%22locations%22%3A%5B%22https%3A%2F%2Fserver%2Eexample%2Ecom%22%5D%7D%5D&redirect_uri=http%3A%2F%2Flocalhost%3A8881%2Fcb&client_id=test-client&scope=openid',
    );
  });
  it('create an authorization request url with authorization_details object property', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._state.endpointMetadata?.credentialIssuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    await expect(
      client.createAuthorizationRequestUrl({
        pkce: {
          codeChallengeMethod: CodeChallengeMethod.S256,
          codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        },
        authorizationRequest: {
          authorizationDetails: {
            type: 'openid_credential',
            format: 'ldp_vc',
            credential_definition: {
              '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
              types: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
          },
          redirectUri: 'http://localhost:8881/cb',
        },
      }),
    ).resolves.toEqual(
      'https://server.example.com/v1/auth/authorize?response_type=code&code_challenge_method=S256&code_challenge=mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs&authorization_details=%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22ldp_vc%22%2C%22credential_definition%22%3A%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fexamples%2Fv1%22%5D%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%2C%22locations%22%3A%5B%22https%3A%2F%2Fserver%2Eexample%2Ecom%22%5D%7D&redirect_uri=http%3A%2F%2Flocalhost%3A8881%2Fcb&client_id=test-client&scope=openid',
    );
  });
  it('create an authorization request url with authorization_details and scope', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._state.endpointMetadata.credentialIssuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    await expect(
      client.createAuthorizationRequestUrl({
        pkce: {
          codeChallengeMethod: CodeChallengeMethod.S256,
          codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        },
        authorizationRequest: {
          authorizationDetails: {
            type: 'openid_credential',
            format: 'ldp_vc',
            locations: ['https://test.com'],
            credential_definition: {
              '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
              types: ['VerifiableCredential', 'UniversityDegreeCredential'],
            },
          },
          scope: 'openid',
          redirectUri: 'http://localhost:8881/cb',
        },
      }),
    ).resolves.toEqual(
      'https://server.example.com/v1/auth/authorize?response_type=code&code_challenge_method=S256&code_challenge=mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs&authorization_details=%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22ldp_vc%22%2C%22locations%22%3A%5B%22https%3A%2F%2Ftest%2Ecom%22%2C%22https%3A%2F%2Fserver%2Eexample%2Ecom%22%5D%2C%22credential_definition%22%3A%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fexamples%2Fv1%22%5D%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%7D&redirect_uri=http%3A%2F%2Flocalhost%3A8881%2Fcb&client_id=test-client&scope=openid',
    );
  });

  it('it should respond with insufficient_authorization when no sessions are provided', async () => {
    const url = new URL(`${MOCK_URL}/authorize-challenge`);
    const responseBody = {
      error: 'insufficient_authorization',
      auth_session: '123456789',
      presentation: '/authorize?client_id=..&request_uri=https://rp.example.com/oidc/request/1234',
    };
    (await client.retrieveServerMetadata()).authorization_challenge_endpoint = url.toString();

    nock(url.origin).post(url.pathname, { client_id: client.clientId }).times(1).reply(400, responseBody);

    await expect(client.acquireAuthorizationChallengeCode({ clientId: client.clientId })).rejects.toEqual({
      error: 'insufficient_authorization',
      auth_session: '123456789',
      presentation: '/authorize?client_id=..&request_uri=https://rp.example.com/oidc/request/1234',
    });
  });

  it('it should successfully respond with a authorization code when authorization challenge is used', async () => {
    const url = new URL(`${MOCK_URL}/authorize-challenge`);
    const responseBody = {
      authorization_code: 'test_authorization_code',
    };
    (await client.retrieveServerMetadata()).authorization_challenge_endpoint = url.toString();

    const authSession = 'test-authSession';
    const presentationDuringIssuanceSession = 'test-presentationDuringIssuanceSession';

    nock(url.origin)
      .post(url.pathname, {
        client_id: client.clientId,
        auth_session: authSession,
        presentation_during_issuance_session: presentationDuringIssuanceSession,
      })
      .times(1)
      .reply(200, responseBody);

    const response = await client.acquireAuthorizationChallengeCode({ clientId: client.clientId, authSession, presentationDuringIssuanceSession });

    expect(response).toBeDefined();
    expect(response.authorization_code).toEqual(responseBody.authorization_code);
  });
});

it('should return true when calling isEbsi function', async () => {
  nock(MOCK_URL).get(/.*/).reply(200, {});
  nock(MOCK_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, {});
  nock(MOCK_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {});
  const client = await OpenID4VCIClientV1_0_11.fromURI({
    clientId: 'test-client',
    uri: 'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fserver.example.com%22%2C%20%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22VerifiableAttestation%22%2C%22CTWalletSameAuthorisedInTime%22%5D%2C%22trust_framework%22%3A%7B%22name%22%3A%22ebsi%22%2C%22type%22%3A%22Accreditation%22%2C%22uri%22%3A%22TIR%20link%20towards%20accreditation%22%7D%7D%5D%7D',
    createAuthorizationRequestURL: false,
  });

  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  client._state.endpointMetadata?.credentialIssuerMetadata = {
    credentials_supported: {
      TestCredential: {
        trust_framework: {
          name: 'ebsi_trust',
        },
      },
    },
  };
  expect(client.isEBSI()).toBe(true);
});
