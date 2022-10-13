import {generateKeyPairSync} from "crypto";

import * as jose from 'jose'
import nock from 'nock';

import {VcIssuanceClient} from '../src/main/VcIssuanceClient';
import {
  CredentialRequest,
  CredentialResponse,
  CredentialResponseError,
  CredentialResponseErrorCode,
  JWTSignerArgs, ProofOfPossession,
} from '../src/main/types';

const partialJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMS9rZXlzLzEifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOjE2NTkxNDU5MjQsIm5vbmNlIjoidFppZ25zbkZicCJ9"

const signJWT = async (args: JWTSignerArgs): Promise<string> => {
  const {header, payload, privateKey} = args
  return await new jose.SignJWT({...payload})
  .setProtectedHeader({...header, alg: 'RS256'})
  .sign(privateKey)
}

const jwtArgs: JWTSignerArgs = {
  header: {
    alg: "RS256",
    kid: "did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1"
  },
  payload: {
    iss: "s6BhdRkqt3",
    aud: "https://server.example.com",
    iat: 1659145924,
    nonce: "tZignsnFbp"
  },
  privateKey: undefined
}


beforeAll(async () => {
  jwtArgs.privateKey = generateKeyPairSync("rsa", {
    modulusLength: 4096
  }).privateKey
})

describe('VcIssuanceClient ', () => {
  it('should build correctly provided with correct params', function () {
    const vcIssuanceClient = VcIssuanceClient.builder()
    .withCredentialRequestUrl('https://oidc4vci.demo.spruceid.com/credential')
    .withFormat('jwt_vc')
    .build();
    expect(vcIssuanceClient._issuanceRequestOpts.credentialRequestUrl).toBe('https://oidc4vci.demo.spruceid.com/credential');
  });

  it('should build credential request correctly', async () => {
    const vcIssuanceClient = VcIssuanceClient.builder()
    .withCredentialRequestUrl('https://oidc4vci.demo.spruceid.com/credential')
    .withCredentialRequestUrl('oidc4vci.demo.spruceid.com/credential')
    .withFormat('jwt_vc')
    .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
    .build();
    const proof: ProofOfPossession = await vcIssuanceClient.createProofOfPossession({
      jwtSignerArgs: jwtArgs,
      jwtSignerCallback: (args) => signJWT(args)
    })
    const credentialRequest: CredentialRequest = vcIssuanceClient.createCredentialRequest({ proof });
    expect(credentialRequest.proof.jwt.includes(partialJWT)).toBeTruthy()
    expect(credentialRequest.type).toBe(
        'https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential'
    );
  });

  it('should get fail credential response', async function () {
    nock('https://oidc4vci.demo.spruceid.com').post(/credential/).reply(400, {
      error: CredentialResponseErrorCode.UNSUPPORTED_FORMAT,
      error_description: 'This is a mock error message'
    });
    const vcIssuanceClient = VcIssuanceClient.builder()
    .withCredentialRequestUrl('https://oidc4vci.demo.spruceid.com/credential')
    .withFormat('ldp_vc')
    .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
    .build();
    const proof: ProofOfPossession = await vcIssuanceClient.createProofOfPossession({
      jwtSignerArgs: jwtArgs,
      jwtSignerCallback: (args) => signJWT(args)
    })
    const credentialRequest: CredentialRequest = vcIssuanceClient.createCredentialRequest({ proof });
    expect(credentialRequest.proof.jwt.includes(partialJWT)).toBeTruthy()
    const result: CredentialResponseError | CredentialResponse = await vcIssuanceClient.sendCredentialRequest(credentialRequest);
    expect(result['error']).toBe('unsupported_format');
  });

  it('should get success credential response', async function () {
    nock('https://oidc4vci.demo.spruceid.com').post(/credential/).reply(200, {
      format: 'jwt-vc',
      credential: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL2V4YW1wbGVzL3YxIl0sImlkIjoiaHR0cDovL2V4YW1wbGUuZWR1L2NyZWRlbnRpYWxzLzM3MzIiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVW5pdmVyc2l0eURlZ3JlZUNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiaHR0cHM6Ly9leGFtcGxlLmVkdS9pc3N1ZXJzLzU2NTA0OSIsImlzc3VhbmNlRGF0ZSI6IjIwMTAtMDEtMDFUMDA6MDA6MDBaIiwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEiLCJkZWdyZWUiOnsidHlwZSI6IkJhY2hlbG9yRGVncmVlIiwibmFtZSI6IkJhY2hlbG9yIG9mIFNjaWVuY2UgYW5kIEFydHMifX19LCJpc3MiOiJodHRwczovL2V4YW1wbGUuZWR1L2lzc3VlcnMvNTY1MDQ5IiwibmJmIjoxMjYyMzA0MDAwLCJqdGkiOiJodHRwOi8vZXhhbXBsZS5lZHUvY3JlZGVudGlhbHMvMzczMiIsInN1YiI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMSJ9.z5vgMTK1nfizNCg5N-niCOL3WUIAL7nXy-nGhDZYO_-PNGeE-0djCpWAMH8fD8eWSID5PfkPBYkx_dfLJnQ7NA'
    });
    const vcIssuanceClient = VcIssuanceClient.builder()
    .withCredentialRequestUrl('https://oidc4vci.demo.spruceid.com/credential')
    .withFormat('jwt_vc')
    .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
    .build();
    const proof: ProofOfPossession = await vcIssuanceClient.createProofOfPossession({
      jwtSignerArgs: jwtArgs,
      jwtSignerCallback: (args) => signJWT(args)
    })
    const credentialRequest: CredentialRequest = vcIssuanceClient.createCredentialRequest({ proof });
    expect(credentialRequest.proof.jwt.includes(partialJWT)).toBeTruthy()
    const result: CredentialResponseError | CredentialResponse = await vcIssuanceClient.sendCredentialRequest(credentialRequest);
    expect(result['credential']).toBeDefined();
  });
});
