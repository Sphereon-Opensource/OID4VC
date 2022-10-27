import { KeyObject } from 'crypto';

import * as jose from 'jose';
import { KeyLike, VerifyOptions } from 'jose/dist/types/types';
import nock from 'nock';
import * as u8a from 'uint8arrays';

import {
  createProofOfPossession,
  CredentialRequest,
  CredentialRequestClient,
  CredentialRequestClientBuilder,
  CredentialResponse,
  ErrorResponse,
  IssuanceInitiation,
  JWS_NOT_VALID,
  JWTSignerArgs,
  MetadataClient,
  ProofOfPossession,
} from '../lib';

import { WALT_OID4VCI_METADATA } from './MetadataMocks';

const partialJWT =
  'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMS9rZXlzLzEifQ.eyJhdWQiOiJodHRwczovL29pZGM0dmNpLmRlbW8uc3BydWNlaWQuY29tL2NyZWRlbnRpYWwiLCJp';

// Must be JWS
const signJWT = async (args: JWTSignerArgs): Promise<string> => {
  const { header, payload, privateKey } = args;
  return await new jose.CompactSign(u8a.fromString(JSON.stringify({ ...payload })))
    .setProtectedHeader({ ...header, alg: args.header.alg })
    .sign(privateKey);
};

const verifyJWT = async (args: { jws: string | Uint8Array; key: KeyLike | Uint8Array; options?: VerifyOptions }): Promise<void> => {
  await jose.compactVerify(args.jws, args.key, args.options);
};

const jwtArgs: JWTSignerArgs = {
  header: {
    alg: 'ES256',
    kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1',
  },
  payload: {
    iss: 's6BhdRkqt3',
    nonce: 'tZignsnFbp',
    jti: 'tZignsnFbp223',
  },
  privateKey: undefined,
  publicKey: undefined,
};

beforeAll(async () => {
  const keyPair = await jose.generateKeyPair('ES256');
  jwtArgs.privateKey = keyPair.privateKey as KeyObject;
  jwtArgs.publicKey = keyPair.publicKey as KeyObject;
});

describe('Credential Request Client ', () => {
  it('should build correctly provided with correct params', function () {
    const credReqClient = CredentialRequestClient.builder()
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .build();
    expect(credReqClient._issuanceRequestOpts.credentialEndpoint).toBe('https://oidc4vci.demo.spruceid.com/credential');
  });

  it('should build credential request correctly', async () => {
    const credReqClient = CredentialRequestClient.builder()
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await createProofOfPossession({
      issuerURL: credReqClient.getCredentialEndpoint(),
      jwtSignerArgs: jwtArgs,
      jwtSignerCallback: (args) => signJWT(args),
      jwtVerifyCallback: (args) => verifyJWT(args),
    });
    const credentialRequest: CredentialRequest = await credReqClient.createCredentialRequest(proof);
    expect(credentialRequest.proof.jwt).toContain(partialJWT);
    expect(credentialRequest.type).toBe('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential');
  });

  it('should get a failed credential response with an unsupported format', async function () {
    const basePath = 'https://sphereonjunit2022101301.com/';

    nock(basePath).post(/.*/).reply(200, {
      error: 'unsupported_format',
      error_description: 'This is a mock error message',
    });

    const credReqClient = CredentialRequestClient.builder()
      .withCredentialEndpoint(basePath + '/credential')
      .withFormat('ldp_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await createProofOfPossession({
      issuerURL: credReqClient.getCredentialEndpoint(),
      jwtSignerArgs: jwtArgs,
      jwtSignerCallback: (args) => signJWT(args),
      jwtVerifyCallback: (args) => verifyJWT(args),
    });
    const credentialRequest: CredentialRequest = await credReqClient.createCredentialRequest(proof);
    expect(credentialRequest.proof.jwt.includes(partialJWT)).toBeTruthy();
    const result: ErrorResponse | CredentialResponse = await credReqClient.acquireCredentialsUsingRequest(credentialRequest);
    expect(result['error']).toBe('unsupported_format');
  });

  it('should get success credential response', async function () {
    const mockedVC =
      'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzU2NTA0OSIsImlzc3VhbmNlRGF0ZSI6IjIwMTAtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19LCJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvNTY1MDQ5IiwibmJmIjoxMjYyMzA0MDAwLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9.z5vgMTK1nfizNCg5N-niCOL3WUIAL7nXy-nGhDZYO_-PNGeE-0djCpWAMH8fD8eWSID5PfkPBYkx_dfLJnQ7NA';
    nock('https://oidc4vci.demo.spruceid.com')
      .post(/credential/)
      .reply(200, {
        format: 'jwt-vc',
        credential: mockedVC,
      });
    const credReqClient = CredentialRequestClient.builder()
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await createProofOfPossession({
      issuerURL: credReqClient.getCredentialEndpoint(),
      jwtSignerArgs: jwtArgs,
      jwtSignerCallback: (args) => signJWT(args),
    });
    const credentialRequest: CredentialRequest = await credReqClient.createCredentialRequest(proof);
    expect(credentialRequest.proof.jwt.includes(partialJWT)).toBeTruthy();
    const result: ErrorResponse | CredentialResponse = await credReqClient.acquireCredentialsUsingRequest(credentialRequest);
    expect(result['credential']).toEqual(mockedVC);
  });
  it('should fail creating a proof of possession with simple verification', async () => {
    const credReqClient = CredentialRequestClient.builder()
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    await expect(
      createProofOfPossession({
        issuerURL: credReqClient.getCredentialEndpoint(),
        jwtSignerArgs: jwtArgs,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        jwtSignerCallback: (_args) => Promise.resolve('invalid_jws'),
      })
    ).rejects.toThrow(Error(JWS_NOT_VALID));
  });
  it('should fail creating a proof of possession with verify callback function', async () => {
    const credReqClient = CredentialRequestClient.builder()
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    await expect(
      createProofOfPossession({
        issuerURL: credReqClient.getCredentialEndpoint(),
        jwtSignerArgs: jwtArgs,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        jwtSignerCallback: (_args) => Promise.resolve('invalid_jws'),
        jwtVerifyCallback: (args) => verifyJWT(args),
      })
    ).rejects.toThrow(Error(JWS_NOT_VALID));
  });
});

describe('Credential Request Client witk Walt.id ', () => {
  it('should have correct metadata endpoints', async function () {
    const WALT_IRR_URI =
      'openid-initiate-issuance://?issuer=https%3A%2F%2Fjff.walt.id%2Fissuer-api%2Foidc%2F&credential_type=OpenBadgeCredential&pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE&user_pin_required=false';
    const inititation = IssuanceInitiation.fromURI(WALT_IRR_URI);

    const metadata = await MetadataClient.retrieveAllMetadataFromInitiation(inititation);
    expect(metadata.credential_endpoint).toEqual(WALT_OID4VCI_METADATA.credential_endpoint);
    expect(metadata.token_endpoint).toEqual(WALT_OID4VCI_METADATA.token_endpoint);

    const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiation(inititation, metadata).build();
    expect(credReqClient._issuanceRequestOpts.credentialEndpoint).toBe(WALT_OID4VCI_METADATA.credential_endpoint);
  });
});
