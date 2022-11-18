import nock from 'nock';

import {
  AccessTokenClient,
  AccessTokenResponse,
  Alg,
  CredentialRequestClientBuilder,
  IssuanceInitiation,
  JwtArgs,
  ProofOfPossession,
  Typ,
} from '../lib';
import { ProofOfPossessionBuilder } from '../lib/ProofOfPossessionBuilder';

export const UNIT_TEST_TIMEOUT = 30000;

const ISSUER_URL = 'https://issuer.research.identiproof.io';
const jwtArgs = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: Typ.JWT },
  payload: { iss: 's6BhdRkqt3', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: 'sphereon' },
  privateKey: undefined,
  publicKey: undefined,
};

describe('OID4VCI-Client should', () => {
  const INITIATE_QR_DATA =
    'openid-initiate-issuance://?issuer=https%3A%2F%2Fissuer.research.identiproof.io&credential_type=OpenBadgeCredentialUrl&pre-authorized_code=4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp&user_pin_required=true';

  it(
    'succeed with a full flow',
    async () => {
      /* Convert the URI into an object */
      const initiationWithUrl = IssuanceInitiation.fromURI(INITIATE_QR_DATA);

      expect(initiationWithUrl.baseUrl).toEqual('openid-initiate-issuance://');
      expect(initiationWithUrl.issuanceInitiationRequest).toEqual({
        credential_type: 'OpenBadgeCredentialUrl',
        issuer: ISSUER_URL,
        'pre-authorized_code':
          '4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp',
        user_pin_required: 'true',
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
      nock(ISSUER_URL)
        .post(/token.*/)
        .reply(200, JSON.stringify(mockedAccessTokenResponse));

      /* The actual access token calls */
      const accessTokenClient: AccessTokenClient = new AccessTokenClient();
      const accessTokenResponse = await accessTokenClient.acquireAccessTokenUsingIssuanceInitiation(initiationWithUrl, {
        pin: '1234',
      });
      expect(accessTokenResponse.successBody).toEqual(mockedAccessTokenResponse);
      // Get the credential
      const mockedVC =
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzU2NTA0OSIsImlzc3VhbmNlRGF0ZSI6IjIwMTAtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19LCJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvNTY1MDQ5IiwibmJmIjoxMjYyMzA0MDAwLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9.z5vgMTK1nfizNCg5N-niCOL3WUIAL7nXy-nGhDZYO_-PNGeE-0djCpWAMH8fD8eWSID5PfkPBYkx_dfLJnQ7NA';
      nock(ISSUER_URL)
        .post(/credential/)
        .reply(200, {
          format: 'jwt-vc',
          credential: mockedVC,
        });
      const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiation(initiationWithUrl)
        .withFormat('jwt_vc')
        .withTokenFromResponse(accessTokenResponse.successBody)
        .build();
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      async function proofOfPossessionCallbackFunction(_args: JwtArgs, _kid: string): Promise<string> {
        return 'ey.val.ue';
      }

      //TS2322: Type '(args: ProofOfPossessionCallbackArgs) => Promise<string>'
      // is not assignable to type 'ProofOfPossessionCallback'.
      // Types of parameters 'args' and 'args' are incompatible.
      // Property 'kid' is missing in type '{ header: unknown; payload: unknown; }' but required in type 'ProofOfPossessionCallbackArgs'.
      const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromProofCallbackArgs({
        proofOfPossessionCallback: proofOfPossessionCallbackFunction,
      })
        .withEndpointMetadata({
          issuer: 'https://issuer.research.identiproof.io',
          credential_endpoint: 'https://issuer.research.identiproof.io/credential',
          token_endpoint: 'https://issuer.research.identiproof.io/token',
        })
        .withKid('did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1')
        .withJwtArgs(jwtArgs)
        .build();
      const credResponse = await credReqClient.acquireCredentialsUsingProof(proof, {});
      expect(credResponse.successBody.credential).toEqual(mockedVC);
    },
    UNIT_TEST_TIMEOUT
  );
});
