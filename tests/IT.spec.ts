import { KeyObject } from 'crypto';

import * as jose from 'jose';
import { KeyLike, VerifyOptions } from 'jose/dist/types/types';
import nock from 'nock';
import * as u8a from 'uint8arrays';

import {
  AccessTokenClient,
  AccessTokenResponse,
  CredentialRequestClientBuilder,
  CredentialResponse,
  IssuanceInitiation,
  JWTSignerArgs,
  ProofOfPossessionOpts,
} from '../lib';

export const UNIT_TEST_TIMEOUT = 30000;

const ISSUER_URL = 'https://issuer.research.identiproof.io';
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
      const accessTokenResponse = await accessTokenClient.acquireAccessTokenUsingIssuanceInitiation(initiationWithUrl, 'sphereon-client-id', {
        pin: '1234',
      });

      expect(accessTokenResponse).toEqual(mockedAccessTokenResponse);

      const keyPair = await jose.generateKeyPair('ES256');
      // Get the credential

      const mockedVC =
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzU2NTA0OSIsImlzc3VhbmNlRGF0ZSI6IjIwMTAtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19LCJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvNTY1MDQ5IiwibmJmIjoxMjYyMzA0MDAwLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9.z5vgMTK1nfizNCg5N-niCOL3WUIAL7nXy-nGhDZYO_-PNGeE-0djCpWAMH8fD8eWSID5PfkPBYkx_dfLJnQ7NA';
      nock(ISSUER_URL)
        .post(/credential/)
        .reply(200, {
          format: 'jwt-vc',
          credential: mockedVC,
        });

      const signJWT = async (args: JWTSignerArgs): Promise<string> => {
        const { header, payload, privateKey } = args;
        return await new jose.CompactSign(u8a.fromString(JSON.stringify({ ...payload })))
          .setProtectedHeader({ ...header, alg: args.header.alg })
          .sign(privateKey);
      };

      const verifyJWT = async (args: { jws: string | Uint8Array; key: KeyLike | Uint8Array; options?: VerifyOptions }): Promise<void> => {
        await jose.compactVerify(args.jws, args.key, args.options);
      };
      const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiation(initiationWithUrl)
        .withFormat('jwt_vc')
        .withTokenFromResponse(accessTokenResponse as AccessTokenResponse)
        .build();
      const proofOpts: ProofOfPossessionOpts = {
        clientId: 'sphereon-client-id',
        issuerURL: ISSUER_URL,
        jwtSignerArgs: {
          header: {
            alg: 'ES256',
            kid: 'did:example:123',
          },
          payload: {
            nonce: mockedAccessTokenResponse.c_nonce,
            jti: 'new-nonce',
          },
          privateKey: keyPair.privateKey as KeyObject,
          publicKey: keyPair.publicKey as KeyObject,
        },
        jwtSignerCallback: (args) => signJWT(args),
        jwtVerifyCallback: (args) => verifyJWT(args),
      };
      const credResponse = (await credReqClient.acquireCredentialsUsingProof(proofOpts, {})) as CredentialResponse;
      expect(credResponse.credential).toEqual(mockedVC);
    },
    UNIT_TEST_TIMEOUT
  );
});
