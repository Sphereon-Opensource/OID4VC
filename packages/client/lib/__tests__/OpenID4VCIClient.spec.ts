import { AuthzFlowType, CodeChallengeMethod } from '@sphereon/oid4vci-common';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock';

import { OpenID4VCIClient } from '../OpenID4VCIClient';

const MOCK_URL = 'https://server.example.com/';

describe('OpenID4VCIClient should', () => {
  let client: OpenID4VCIClient;

  beforeEach(async () => {
    nock(MOCK_URL).get(/.*/).reply(200, {});
    client = await OpenID4VCIClient.fromURI({
      uri: 'openid-initiate-issuance://?issuer=https://server.example.com&credential_type=TestCredential',
      flowType: AuthzFlowType.AUTHORIZATION_CODE_FLOW,
    });
  });

  afterEach(() => {
    nock.cleanAll();
  });

  it('should create successfully construct an authorization request url', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._endpointMetadata?.issuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;
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
    client._endpointMetadata?.issuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

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
  it('throw an error if no scope and no authorization_details is provided', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._endpointMetadata?.issuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    expect(() => {
      client.createAuthorizationRequestUrl({
        clientId: 'test-client',
        codeChallengeMethod: CodeChallengeMethod.SHA256,
        codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        redirectUri: 'http://localhost:8881/cb',
      });
    }).toThrow(Error('Please provide a scope or authorization_details'));
  });
  it('create an authorization request url with authorization_details array property', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._endpointMetadata.issuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    expect(
      client.createAuthorizationRequestUrl({
        clientId: 'test-client',
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
          {
            type: 'openid_credential',
            format: 'mso_mdoc',
            doctype: 'org.iso.18013.5.1.mDL',
          },
        ],
        redirectUri: 'http://localhost:8881/cb',
      })
    ).toEqual(
      'https://server.example.com/v1/auth/authorize?response_type=code&client_id=test-client&code_challenge_method=S256&code_challenge=mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs&authorization_details=%5B%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22ldp_vc%22%2C%22credential_definition%22%3A%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fexamples%2Fv1%22%5D%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%2C%22locations%22%3A%22https%3A%2F%2Fserver%2Eexample%2Ecom%22%7D%2C%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22mso_mdoc%22%2C%22doctype%22%3A%22org%2Eiso%2E18013%2E5%2E1%2EmDL%22%2C%22locations%22%3A%22https%3A%2F%2Fserver%2Eexample%2Ecom%22%7D%5D&redirect_uri=http%3A%2F%2Flocalhost%3A8881%2Fcb'
    );
  });
  it('create an authorization request url with authorization_details object property', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._endpointMetadata.issuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    expect(
      client.createAuthorizationRequestUrl({
        clientId: 'test-client',
        codeChallengeMethod: CodeChallengeMethod.SHA256,
        codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
        authorizationDetails: {
          type: 'openid_credential',
          format: 'ldp_vc',
          credential_definition: {
            '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
            types: ['VerifiableCredential', 'UniversityDegreeCredential'],
          },
        },
        redirectUri: 'http://localhost:8881/cb',
      })
    ).toEqual(
      'https://server.example.com/v1/auth/authorize?response_type=code&client_id=test-client&code_challenge_method=S256&code_challenge=mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs&authorization_details=%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22ldp_vc%22%2C%22credential_definition%22%3A%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fexamples%2Fv1%22%5D%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%2C%22locations%22%3A%22https%3A%2F%2Fserver%2Eexample%2Ecom%22%7D&redirect_uri=http%3A%2F%2Flocalhost%3A8881%2Fcb'
    );
  });
  it('create an authorization request url with authorization_details and scope', async () => {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    client._endpointMetadata.issuerMetadata.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`;

    expect(
      client.createAuthorizationRequestUrl({
        clientId: 'test-client',
        codeChallengeMethod: CodeChallengeMethod.SHA256,
        codeChallenge: 'mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs',
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
      })
    ).toEqual(
      'https://server.example.com/v1/auth/authorize?response_type=code&client_id=test-client&code_challenge_method=S256&code_challenge=mE2kPHmIprOqtkaYmESWj35yz-PB5vzdiSu0tAZ8sqs&authorization_details=%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22ldp_vc%22%2C%22locations%22%3A%5B%22https%3A%2F%2Ftest%2Ecom%22%2C%22https%3A%2F%2Fserver%2Eexample%2Ecom%22%5D%2C%22credential_definition%22%3A%7B%22%40context%22%3A%5B%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fv1%22%2C%22https%3A%2F%2Fwww%2Ew3%2Eorg%2F2018%2Fcredentials%2Fexamples%2Fv1%22%5D%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%7D&redirect_uri=http%3A%2F%2Flocalhost%3A8881%2Fcb&scope=openid'
    );
  });
});
