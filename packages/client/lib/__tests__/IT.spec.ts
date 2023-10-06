import {
  AccessTokenResponse,
  Alg,
  CredentialOfferRequestWithBaseUrl,
  Jwt,
  OpenId4VCIVersion,
  ProofOfPossession,
  WellKnownEndpoints,
} from '@sphereon/oid4vci-common';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock';

import { AccessTokenClient, CredentialRequestClientBuilder, OpenID4VCIClient, ProofOfPossessionBuilder } from '..';
import { CredentialOfferClient } from '../CredentialOfferClient';

import { IDENTIPROOF_AS_METADATA, IDENTIPROOF_AS_URL, IDENTIPROOF_ISSUER_URL, IDENTIPROOF_OID4VCI_METADATA } from './MetadataMocks';

export const UNIT_TEST_TIMEOUT = 30000;

const ISSUER_URL = 'https://issuer.research.identiproof.io';
const jwt = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: 'openid4vci-proof+jwt' },
  payload: { iss: 'test-clientId', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: ISSUER_URL },
};

describe('OID4VCI-Client should', () => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async function proofOfPossessionCallbackFunction(_args: Jwt, _kid?: string): Promise<string> {
    return 'ey.val.ue';
  }
  beforeEach(() => {
    nock.cleanAll();
  });
  afterEach(() => {
    nock.cleanAll();
  });

  // Access token mocks
  const mockedAccessTokenResponse: AccessTokenResponse = {
    access_token: 'ey6546.546654.64565',
    authorization_pending: false,
    c_nonce: 'c_nonce2022101300',
    c_nonce_expires_in: 2025101300,
    interval: 2025101300,
    token_type: 'Bearer',
  };
  const mockedVC =
    'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzU2NTA0OSIsImlzc3VhbmNlRGF0ZSI6IjIwMTAtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19LCJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvNTY1MDQ5IiwibmJmIjoxMjYyMzA0MDAwLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9.z5vgMTK1nfizNCg5N-niCOL3WUIAL7nXy-nGhDZYO_-PNGeE-0djCpWAMH8fD8eWSID5PfkPBYkx_dfLJnQ7NA';
  const INITIATE_QR =
    'openid-initiate-issuance://?issuer=https%3A%2F%2Fissuer.research.identiproof.io&credential_type=OpenBadgeCredentialUrl&pre-authorized_code=4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp&user_pin_required=true';
  const OFFER_QR =
    'openid-credential-offer://credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D';

  function succeedWithAFullFlowWithClientSetup() {
    nock(IDENTIPROOF_ISSUER_URL).get('/.well-known/openid-credential-issuer').reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
    nock(IDENTIPROOF_AS_URL).get('/.well-known/oauth-authorization-server').reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA));
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {});
    nock(IDENTIPROOF_AS_URL)
      .post(/oauth2\/token.*/)
      .reply(200, JSON.stringify(mockedAccessTokenResponse));
    nock(ISSUER_URL)
      .post(/credential/)
      .reply(200, {
        format: 'jwt-vc',
        credential: mockedVC,
      });
  }

  it('succeed with a full flow with the client using OpenID4VCI version 9', async () => {
    succeedWithAFullFlowWithClientSetup();
    const client = await OpenID4VCIClient.fromURI({
      uri: INITIATE_QR,
      kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1',
      alg: Alg.ES256,
      clientId: 'test-clientId',
    });
    await assertionOfsucceedWithAFullFlowWithClient(client);
  });

  test.skip('succeed with a full flow wit the client using OpenID4VCI version 11', async () => {
    succeedWithAFullFlowWithClientSetup();
    const client = await OpenID4VCIClient.fromURI({
      uri: OFFER_QR,
      kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1',
      alg: Alg.ES256,
      clientId: 'test-clientId',
    });
    await assertionOfsucceedWithAFullFlowWithClient(client);
  });

  async function assertionOfsucceedWithAFullFlowWithClient(client: OpenID4VCIClient) {
    expect(client.credentialOffer).toBeDefined();
    expect(client.endpointMetadata).toBeDefined();
    expect(client.getIssuer()).toEqual('https://issuer.research.identiproof.io');
    expect(client.getCredentialEndpoint()).toEqual('https://issuer.research.identiproof.io/credential');
    expect(client.getAccessTokenEndpoint()).toEqual('https://auth.research.identiproof.io/oauth2/token');

    const accessToken = await client.acquireAccessToken({ pin: '1234' });
    expect(accessToken).toEqual(mockedAccessTokenResponse);

    const credentialResponse = await client.acquireCredentials({
      credentialTypes: 'OpenBadgeCredential',
      format: 'jwt_vc_json-ld',
      proofCallbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
    });
    expect(credentialResponse.credential).toEqual(mockedVC);
  }

  it(
    'succeed with a full flow without the client',
    async () => {
      /* Convert the URI into an object */
      const credentialOffer: CredentialOfferRequestWithBaseUrl = await CredentialOfferClient.fromURI(INITIATE_QR);

      expect(credentialOffer.baseUrl).toEqual('openid-initiate-issuance://');
      expect(credentialOffer.original_credential_offer).toEqual({
        credential_type: ['OpenBadgeCredentialUrl'],
        issuer: ISSUER_URL,
        'pre-authorized_code':
          '4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp',
        user_pin_required: 'true',
      });

      nock(ISSUER_URL)
        .post(/token.*/)
        .reply(200, JSON.stringify(mockedAccessTokenResponse));

      /* The actual access token calls */
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();
      const accessTokenResponse = await accessTokenClient.acquireAccessToken({ credentialOffer: credentialOffer, pin: '1234' });
      expect(accessTokenResponse.successBody).toEqual(mockedAccessTokenResponse);
      // Get the credential
      nock(ISSUER_URL)
        .post(/credential/)
        .reply(200, {
          format: 'jwt-vc',
          credential: mockedVC,
        });
      const credReqClient = CredentialRequestClientBuilder.fromCredentialOffer({ credentialOffer: credentialOffer })
        .withFormat('jwt_vc')

        .withTokenFromResponse(accessTokenResponse.successBody!)
        .build();

      //TS2322: Type '(args: ProofOfPossessionCallbackArgs) => Promise<string>'
      // is not assignable to type 'ProofOfPossessionCallback'.
      // Types of parameters 'args' and 'args' are incompatible.
      // Property 'kid' is missing in type '{ header: unknown; payload: unknown; }' but required in type 'ProofOfPossessionCallbackArgs'.
      const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
        jwt,
        callbacks: {
          signCallback: proofOfPossessionCallbackFunction,
        },
        version: OpenId4VCIVersion.VER_1_0_11,
      })
        .withEndpointMetadata({
          issuer: 'https://issuer.research.identiproof.io',
          credential_endpoint: 'https://issuer.research.identiproof.io/credential',
          token_endpoint: 'https://issuer.research.identiproof.io/token',
        })
        .withKid('did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1')
        .build();
      const credResponse = await credReqClient.acquireCredentialsUsingProof({ proofInput: proof });
      expect(credResponse.successBody?.credential).toEqual(mockedVC);
    },
    UNIT_TEST_TIMEOUT,
  );
});
