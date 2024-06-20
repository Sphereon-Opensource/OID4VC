import {
  AccessTokenResponse,
  Alg,
  CredentialOfferPayloadV1_0_13,
  CredentialOfferRequestWithBaseUrl,
  Jwt,
  OpenId4VCIVersion,
  ProofOfPossession,
  resolveCredentialOfferURI,
  WellKnownEndpoints,
} from '@sphereon/oid4vci-common';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock';

import {
  AccessTokenClient,
  AccessTokenClientV1_0_11,
  CredentialOfferClientV1_0_11,
  CredentialRequestClientBuilder,
  CredentialRequestClientBuilderV1_0_11,
  OpenID4VCIClientV1_0_11,
  ProofOfPossessionBuilder,
} from '..';
import { CredentialOfferClient } from '../CredentialOfferClient';

import { IDENTIPROOF_AS_METADATA, IDENTIPROOF_AS_URL, IDENTIPROOF_ISSUER_URL, IDENTIPROOF_OID4VCI_METADATA } from './MetadataMocks';

export const UNIT_TEST_TIMEOUT = 30000;

const ISSUER_URL = 'https://issuer.research.identiproof.io';
const jwtDid = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: 'openid4vci-proof+jwt' },
  payload: { iss: 'test-clientId', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: ISSUER_URL },
};

const jwtWithoutDid = {
  header: { alg: Alg.ES256, kid: 'ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: 'openid4vci-proof+jwt' },
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
  const INITIATE_QR_V1_0_08 =
    'openid-initiate-issuance://?issuer=https%3A%2F%2Fissuer.research.identiproof.io&credential_type=OpenBadgeCredentialUrl&pre-authorized_code=4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp&user_pin_required=true';
  const OFFER_QR_V1_0_08 =
    'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.research.identiproof.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22adhjhdjajkdkhjhdj%22%2C%22user_pin_required%22%3Atrue%7D%7D%7D';
  const HTTPS_INITIATE_QR =
    'https://issuer.research.identiproof.io?issuer=https%3A%2F%2Fissuer.research.identiproof.io&credential_type=OpenBadgeCredentialUrl&pre-authorized_code=4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp&user_pin_required=true';
  const HTTPS_OFFER_QR_AUTHORIZATION_CODE =
    'https://issuer.research.identiproof.io?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.research.identiproof.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22eyJhbGciOiJSU0Et...FYUaBy%22%7D%7D%7D';
  const HTTPS_OFFER_QR_PRE_AUTHORIZED =
    'https://issuer.research.identiproof.io?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.research.identiproof.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22adhjhdjajkdkhjhdj%22%2C%22user_pin_required%22%3Atrue%7D%7D%7D';

  const INITIATE_QR_V1_0_13 =
    'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%22https://issuer.research.identiproof.io%22,%22credential_configuration_ids%22:%5B%22OpenBadgeCredentialUrl%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%22input_mode%22:%22text%22,%22length%22:22,%22description%22:%22Please%20enter%20the%20serial%20number%20of%20your%20physical%20drivers%20license%22%7D%7D%7D%7D';

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
    const client = await OpenID4VCIClientV1_0_11.fromURI({
      uri: INITIATE_QR_V1_0_08,
      kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1',
      alg: Alg.ES256,
      clientId: 'test-clientId',
    });
    await assertionOfsucceedWithAFullFlowWithClient(client);
  });

  it('succeed with a full flow with the client using OpenID4VCI version 11 and deeplink', async () => {
    succeedWithAFullFlowWithClientSetup();
    const client = await OpenID4VCIClientV1_0_11.fromURI({
      uri: OFFER_QR_V1_0_08,
      kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1',
      alg: Alg.ES256,
      clientId: 'test-clientId',
    });
    await assertionOfsucceedWithAFullFlowWithClient(client);
  });

  it('succeed with a full flow with the client using OpenID4VCI draft < 9 and https', async () => {
    succeedWithAFullFlowWithClientSetup();
    const client = await OpenID4VCIClientV1_0_11.fromURI({
      uri: HTTPS_INITIATE_QR,
      kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1',
      alg: Alg.ES256,
      clientId: 'test-clientId',
    });
    await assertionOfsucceedWithAFullFlowWithClient(client);
  });

  it('should succeed with a full flow with the client using OpenID4VCI draft > 11, https and authorization_code flow', async () => {
    succeedWithAFullFlowWithClientSetup();
    const client = await OpenID4VCIClientV1_0_11.fromURI({
      uri: HTTPS_OFFER_QR_AUTHORIZATION_CODE,
      kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1',
      alg: Alg.ES256,
      clientId: 'test-clientId',
    });
    await assertionOfsucceedWithAFullFlowWithClient(client);
  });

  it('should succeed with a full flow with the client using OpenID4VCI draft > 11, https and preauthorized_code flow', async () => {
    succeedWithAFullFlowWithClientSetup();
    const client = await OpenID4VCIClientV1_0_11.fromURI({
      uri: HTTPS_OFFER_QR_PRE_AUTHORIZED,
      kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1',
      alg: Alg.ES256,
      clientId: 'test-clientId',
    });
    await assertionOfsucceedWithAFullFlowWithClient(client);
  });

  async function assertionOfsucceedWithAFullFlowWithClient(client: OpenID4VCIClientV1_0_11) {
    expect(client.credentialOffer).toBeDefined();
    expect(client.endpointMetadata).toBeDefined();
    expect(client.getIssuer()).toEqual('https://issuer.research.identiproof.io');
    expect(client.getCredentialEndpoint()).toEqual('https://issuer.research.identiproof.io/credential');
    expect(client.getAccessTokenEndpoint()).toEqual('https://auth.research.identiproof.io/oauth2/token');

    const accessToken = await client.acquireAccessToken({ pin: '1234', code: 'ABCD' });
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
    'succeed with a full flow without the client v1_0_11',
    async () => {
      /* Convert the URI into an object */
      const credentialOffer: CredentialOfferRequestWithBaseUrl = await CredentialOfferClientV1_0_11.fromURI(INITIATE_QR_V1_0_08);

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
      const accessTokenClient: AccessTokenClientV1_0_11 = new AccessTokenClientV1_0_11();
      const accessTokenResponse = await accessTokenClient.acquireAccessToken({ credentialOffer: credentialOffer, pin: '1234' });
      expect(accessTokenResponse.successBody).toEqual(mockedAccessTokenResponse);
      // Get the credential
      nock(ISSUER_URL)
        .post(/credential/)
        .reply(200, {
          format: 'jwt-vc',
          credential: mockedVC,
        });
      const credReqClient = CredentialRequestClientBuilderV1_0_11.fromCredentialOffer({ credentialOffer: credentialOffer })
        .withFormat('jwt_vc')

        .withTokenFromResponse(accessTokenResponse.successBody!)
        .build();

      //TS2322: Type '(args: ProofOfPossessionCallbackArgs) => Promise<string>'
      // is not assignable to type 'ProofOfPossessionCallback'.
      // Types of parameters 'args' and 'args' are incompatible.
      // Property 'kid' is missing in type '{ header: unknown; payload: unknown; }' but required in type 'ProofOfPossessionCallbackArgs'.
      const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
        jwt: jwtDid,
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

  it(
    'succeed with a full flow with a not-did-kid  without the client v1_0_11',
    async () => {
      /* Convert the URI into an object */
      const credentialOffer: CredentialOfferRequestWithBaseUrl = await CredentialOfferClientV1_0_11.fromURI(INITIATE_QR_V1_0_08);

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
      const accessTokenClient: AccessTokenClientV1_0_11 = new AccessTokenClientV1_0_11();
      const accessTokenResponse = await accessTokenClient.acquireAccessToken({ credentialOffer: credentialOffer, pin: '1234' });
      expect(accessTokenResponse.successBody).toEqual(mockedAccessTokenResponse);
      // Get the credential
      nock(ISSUER_URL)
      .post(/credential/)
      .reply(200, {
        format: 'jwt-vc',
        credential: mockedVC,
      });
      const credReqClient = CredentialRequestClientBuilderV1_0_11.fromCredentialOffer({ credentialOffer: credentialOffer })
      .withFormat('jwt_vc')

      .withTokenFromResponse(accessTokenResponse.successBody!)
      .build();

      //TS2322: Type '(args: ProofOfPossessionCallbackArgs) => Promise<string>'
      // is not assignable to type 'ProofOfPossessionCallback'.
      // Types of parameters 'args' and 'args' are incompatible.
      // Property 'kid' is missing in type '{ header: unknown; payload: unknown; }' but required in type 'ProofOfPossessionCallbackArgs'.
      const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
        jwt: jwtWithoutDid,
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
      .withKid('ebfeb1f712ebc6f1c276e12ec21/keys/1')
      .build();
      const credResponse = await credReqClient.acquireCredentialsUsingProof({ proofInput: proof });
      expect(credResponse.successBody?.credential).toEqual(mockedVC);
    },
    UNIT_TEST_TIMEOUT,
  );

  it(
    'succeed with a full flow without the client v1_0_13',
    async () => {
      /* Convert the URI into an object */
      const credentialOffer: CredentialOfferRequestWithBaseUrl = await CredentialOfferClient.fromURI(INITIATE_QR_V1_0_13);
      const preAuthorizedCode = 'oaKazRN8I0IbtZ0C7JuMn5';
      expect(credentialOffer.baseUrl).toEqual('openid-credential-offer://');
      expect((credentialOffer.credential_offer as CredentialOfferPayloadV1_0_13).credential_configuration_ids).toEqual(['OpenBadgeCredentialUrl']);
      expect(credentialOffer.original_credential_offer.grants).toEqual({
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthorizedCode,
          tx_code: {
            input_mode: 'text',
            description: 'Please enter the serial number of your physical drivers license',
            length: preAuthorizedCode.length,
          },
        },
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
        jwt: jwtDid,
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
      const credResponse = await credReqClient.acquireCredentialsUsingProof({
        proofInput: proof,
        credentialTypes: credentialOffer.original_credential_offer.credential_configuration_ids[0],
      });
      expect(credResponse.successBody?.credential).toEqual(mockedVC);
    },
    UNIT_TEST_TIMEOUT,
  );

  it(
    'succeed with a full flow with a not-did-kid without the client v1_0_13',
    async () => {
      /* Convert the URI into an object */
      const credentialOffer: CredentialOfferRequestWithBaseUrl = await CredentialOfferClient.fromURI(INITIATE_QR_V1_0_13);
      const preAuthorizedCode = 'oaKazRN8I0IbtZ0C7JuMn5';
      expect(credentialOffer.baseUrl).toEqual('openid-credential-offer://');
      expect((credentialOffer.credential_offer as CredentialOfferPayloadV1_0_13).credential_configuration_ids).toEqual(['OpenBadgeCredentialUrl']);
      expect(credentialOffer.original_credential_offer.grants).toEqual({
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthorizedCode,
          tx_code: {
            input_mode: 'text',
            description: 'Please enter the serial number of your physical drivers license',
            length: preAuthorizedCode.length,
          },
        },
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
        jwt: jwtWithoutDid,
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
      .withKid('ebfeb1f712ebc6f1c276e12ec21/keys/1')
      .build();
      const credResponse = await credReqClient.acquireCredentialsUsingProof({
        proofInput: proof,
        credentialTypes: credentialOffer.original_credential_offer.credential_configuration_ids,
      });
      expect(credResponse.successBody?.credential).toEqual(mockedVC);
    },
    UNIT_TEST_TIMEOUT,
  );
});

describe('OIDVCI-Client for v1_0_13 should', () => {
  const INITIATE_QR_V1_0_13_CREDENCO =
    'openid-credential-offer://mijnkvk.acc.credenco.com/?credential_offer_uri=https%3A%2F%2Fmijnkvk.acc.credenco.com%2Fopenid4vc%2FcredentialOffer%3Fid%3D32fc4ebf-9e31-4149-9877-e3c0b602d559';

  const mockedCredentialOffer = {
    credential_issuer: 'https://mijnkvk.acc.credenco.com',
    credential_configuration_ids: ['BevoegdheidUittreksel_jwt_vc_json'],
    grants: {
      authorization_code: {
        issuer_state: '32fc4ebf-9e31-4149-9877-e3c0b602d559',
      },
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code':
          'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIzMmZjNGViZi05ZTMxLTQxNDktOTg3Ny1lM2MwYjYwMmQ1NTkiLCJpc3MiOiJodHRwczovL21pam5rdmsuYWNjLmNyZWRlbmNvLmNvbSIsImF1ZCI6IlRPS0VOIn0.754aiQ87O0vHYSpRvPqAS9cLOgf-pewdeXbpLziRwsxEp9mENfaXpY62muYpzOaWcYmTOydkzhFul-NDYXJZCA',
      },
    },
  };

  beforeEach(() => {
    // Mock the HTTP GET request to the credential offer URI
    nock('https://mijnkvk.acc.credenco.com')
      .get('/openid4vc/credentialOffer?id=32fc4ebf-9e31-4149-9877-e3c0b602d559')
      .reply(200, mockedCredentialOffer)
      .persist(); // Use .persist() if you want the mock to remain active for multiple tests
  });

  afterEach(() => {
    // Clean up all mocks
    nock.cleanAll();
  });

  /*function succeedWithAFullFlowWithClientSetup() {
    nock(IDENTIPROOF_ISSUER_URL).get('/.well-known/openid-credential-issuer').reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
    nock(IDENTIPROOF_AS_URL).get('/.well-known/oauth-authorization-server').reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA));
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {});
    nock(IDENTIPROOF_AS_URL)
    .post(/oauth2\/token.*!/)
    .reply(200, JSON.stringify(mockedAccessTokenResponse));
    nock(ISSUER_URL)
    .post(/credential/)
    .reply(200, {
      format: 'jwt-vc',
      credential: mockedVC,
    });
  }*/

  it('should successfully resolve the credential offer URI', async () => {
    const uri = 'https://mijnkvk.acc.credenco.com/openid4vc/credentialOffer?id=32fc4ebf-9e31-4149-9877-e3c0b602d559';

    const credentialOffer = await resolveCredentialOfferURI(uri);

    expect(credentialOffer).toEqual(mockedCredentialOffer);
  });

  // TODO: ksadjad remove the skipped test
  it.skip(
    'succeed credenco with a full flow without the client v1_0_13',
    async () => {
      /* Convert the URI into an object */
      // openid-credential-offer://?credential_offer%3D%7B%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.research.identiproof.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%2C%22UniversityDegreeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22adhjhdjajkdkhjhdj%22%2C%22user_pin_required%22%3Atrue%7D%7D%7D
      const credentialOffer: CredentialOfferRequestWithBaseUrl = await CredentialOfferClient.fromURI(INITIATE_QR_V1_0_13_CREDENCO);
      /**
       * {"credential_issuer":"https://mijnkvk.acc.credenco.com","credential_configuration_ids":["BevoegdheidUittreksel_jwt_vc_json"],"grants":{"authorization_code":{"issuer_state":"32fc4ebf-9e31-4149-9877-e3c0b602d559"},"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIzMmZjNGViZi05ZTMxLTQxNDktOTg3Ny1lM2MwYjYwMmQ1NTkiLCJpc3MiOiJodHRwczovL21pam5rdmsuYWNjLmNyZWRlbmNvLmNvbSIsImF1ZCI6IlRPS0VOIn0.754aiQ87O0vHYSpRvPqAS9cLOgf-pewdeXbpLziRwsxEp9mENfaXpY62muYpzOaWcYmTOydkzhFul-NDYXJZCA"}}}
       */
      const preAuthorizedCode =
        'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIzMmZjNGViZi05ZTMxLTQxNDktOTg3Ny1lM2MwYjYwMmQ1NTkiLCJpc3MiOiJodHRwczovL21pam5rdmsuYWNjLmNyZWRlbmNvLmNvbSIsImF1ZCI6IlRPS0VOIn0.754aiQ87O0vHYSpRvPqAS9cLOgf-pewdeXbpLziRwsxEp9mENfaXpY62muYpzOaWcYmTOydkzhFul-NDYXJZCA';
      expect(credentialOffer.baseUrl).toEqual('openid-credential-offer://mijnkvk.acc.credenco.com/');
      expect((credentialOffer.credential_offer as CredentialOfferPayloadV1_0_13).credential_configuration_ids).toEqual([
        'BevoegdheidUittreksel_jwt_vc_json',
      ]);
      expect(credentialOffer.original_credential_offer.grants).toEqual({
        authorization_code: {
          issuer_state: '32fc4ebf-9e31-4149-9877-e3c0b602d559',
        },
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthorizedCode,
        },
      });

      /*nock(ISSUER_URL)
      .post(/token.*!/)
      .reply(200, JSON.stringify(mockedAccessTokenResponse));*/

      /* The actual access token calls */
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();
      const accessTokenResponse = await accessTokenClient.acquireAccessToken({
        credentialOffer: credentialOffer,
        pin: preAuthorizedCode /*, metadata: {}*/,
      });
      expect(accessTokenResponse.successBody).toEqual({});
      /*// Get the credential
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
      const credResponse = await credReqClient.acquireCredentialsUsingProof({
        proofInput: proof,
        credentialTypes: credentialOffer.original_credential_offer.credential_configuration_ids,
      });
      expect(credResponse.successBody?.credential).toEqual(mockedVC);*/
    },
    UNIT_TEST_TIMEOUT,
  );
});
