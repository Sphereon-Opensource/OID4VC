import { CodeChallengeMethod, WellKnownEndpoints } from '@sphereon/oid4vci-common';
import nock from 'nock';

import { OpenID4VCIClient } from '../OpenID4VCIClient';

const MOCK_URL = 'https://server.example.com/';
describe('OpenID4VCIClient', () => {
  let client: OpenID4VCIClient;

  beforeEach(async () => {
    nock(MOCK_URL).get(/.*/).reply(200, {});
    nock(MOCK_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, {});
    nock(MOCK_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {});
    nock(`${MOCK_URL}`).post('/v1/auth/par').reply(201, { request_uri: 'test_uri', expires_in: 90 });
    client = await OpenID4VCIClient.fromURI({
      clientId: 'test-client',
      uri: 'openid-initiate-issuance://?issuer=https://server.example.com&credential_type=TestCredential',
    });
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it('should successfully retrieve the authorization code using PAR', async () => {
    client.endpointMetadata.credentialIssuerMetadata!.pushed_authorization_request_endpoint = `${MOCK_URL}v1/auth/par`;
    client.endpointMetadata.credentialIssuerMetadata!.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;
    const actual = await client.acquirePushedAuthorizationRequestURI({
      codeChallengeMethod: CodeChallengeMethod.SHA256,
      codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
      scope: 'openid TestCredential',
      redirectUri: 'http://localhost:8881/cb',
    });
    expect(actual).toEqual('https://server.example.com/v1/auth/authorize?request_uri=test_uri');
  });

  it('should fail when pushed_authorization_request_endpoint is not present', async () => {
    await expect(() =>
      client.acquirePushedAuthorizationRequestURI({
        codeChallengeMethod: CodeChallengeMethod.SHA256,
        codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        scope: 'openid TestCredential',
        redirectUri: 'http://localhost:8881/cb',
      }),
    ).rejects.toThrow(Error('Server metadata does not contain pushed authorization request endpoint'));
  });

  it('should fail when authorization_details and scope are not present', async () => {
    await expect(() =>
      client.acquirePushedAuthorizationRequestURI({
        codeChallengeMethod: CodeChallengeMethod.SHA256,
        codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        redirectUri: 'http://localhost:8881/cb',
      }),
    ).rejects.toThrow(Error('Please provide a scope or authorization_details'));
  });

  it('should not fail when only authorization_details is present', async () => {
    client.endpointMetadata.credentialIssuerMetadata!.pushed_authorization_request_endpoint = `${MOCK_URL}v1/auth/par`;
    client.endpointMetadata.credentialIssuerMetadata!.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;
    const actual = await client.acquirePushedAuthorizationRequestURI({
      codeChallengeMethod: CodeChallengeMethod.SHA256,
      codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
      authorizationDetails: [
        {
          type: 'openid_credential',
          format: 'ldp_vc',
          credential_definition: {
            '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
            types: ['VerifiableCredential', 'UniversityDegreeCredential'],
          },
        },
      ],
      redirectUri: 'http://localhost:8881/cb',
    });
    expect(actual).toEqual('https://server.example.com/v1/auth/authorize?request_uri=test_uri');
  });

  it('should not fail when only scope is present', async () => {
    client.endpointMetadata.credentialIssuerMetadata!.pushed_authorization_request_endpoint = `${MOCK_URL}v1/auth/par`;
    client.endpointMetadata.credentialIssuerMetadata!.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;
    const actual = await client.acquirePushedAuthorizationRequestURI({
      codeChallengeMethod: CodeChallengeMethod.SHA256,
      codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
      scope: 'openid TestCredential',
      redirectUri: 'http://localhost:8881/cb',
    });
    expect(actual).toEqual('https://server.example.com/v1/auth/authorize?request_uri=test_uri');
  });

  it('should not fail when both authorization_details and scope are present', async () => {
    client.endpointMetadata.credentialIssuerMetadata!.pushed_authorization_request_endpoint = `${MOCK_URL}v1/auth/par`;
    client.endpointMetadata.credentialIssuerMetadata!.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;
    const actual = await client.acquirePushedAuthorizationRequestURI({
      codeChallengeMethod: CodeChallengeMethod.SHA256,
      codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
      authorizationDetails: [
        {
          type: 'openid_credential',
          format: 'ldp_vc',
          credential_definition: {
            '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
            types: ['VerifiableCredential', 'UniversityDegreeCredential'],
          },
        },
      ],
      scope: 'openid TestCredential',
      redirectUri: 'http://localhost:8881/cb',
    });
    expect(actual).toEqual('https://server.example.com/v1/auth/authorize?request_uri=test_uri');
  });
});
