import { AuthzFlowType, CodeChallengeMethod } from '@sphereon/openid4vci-common';
import nock from 'nock';

import { OpenID4VCIClient } from '../OpenID4VCIClient';

const MOCK_URL = 'https://server.example.com/';

describe('OpenID4VCIClient should', () => {
  let client: OpenID4VCIClient;

  beforeEach(async () => {
    nock(MOCK_URL).get(/.*/).reply(200, {});
    client = await OpenID4VCIClient.credentialOffer({
      credentialOfferURI: 'openid-initiate-issuance://?issuer=https://server.example.com&credential_type=TestCredential',
      flowType: AuthzFlowType.AUTHORIZATION_CODE_FLOW,
    });
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it('should create successfully construct an authorization request url', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._serverMetadata.openid4vci_metadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;
    const url = client.createAuthorizationRequestUrl({
      clientId: 'test-client',
      codeChallengeMethod: CodeChallengeMethod.SHA256,
      codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
      scope: 'openid TestCredential',
      redirectUri: 'http://localhost:8881/cb',
    });

    const urlSearchParams = new URLSearchParams(url.split('?')[1]);
    const scope = urlSearchParams.get('scope')?.split(' ');

    expect(scope?.[0]).toBe('openid');
  });
  it('throw an error if authorization endpoint is not set in server metadata', async () => {
    expect(() => {
      client.createAuthorizationRequestUrl({
        clientId: 'test-client',
        codeChallengeMethod: CodeChallengeMethod.SHA256,
        codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        scope: 'openid TestCredential',
        redirectUri: 'http://localhost:8881/cb',
      });
    }).toThrow(Error('Server metadata does not contain authorization endpoint'));
  });
  it("injects 'openid' as the first scope if not provided", async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._serverMetadata.openid4vci_metadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    const url = client.createAuthorizationRequestUrl({
      clientId: 'test-client',
      codeChallengeMethod: CodeChallengeMethod.SHA256,
      codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
      scope: 'TestCredential',
      redirectUri: 'http://localhost:8881/cb',
    });

    const urlSearchParams = new URLSearchParams(url.split('?')[1]);
    const scope = urlSearchParams.get('scope')?.split(' ');

    expect(scope?.[0]).toBe('openid');
  });
  it('throw an error if no scope is provided', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._serverMetadata.openid4vci_metadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    expect(() => {
      client.createAuthorizationRequestUrl({
        clientId: 'test-client',
        codeChallengeMethod: CodeChallengeMethod.SHA256,
        codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        redirectUri: 'http://localhost:8881/cb',
      });
    }).toThrow(Error('Please provide a scope. authorization_details based requests are not supported at this time'));
  });
});
