import { KeyObject } from 'crypto';

import { Alg, CredentialRequest, Jwt, ProofOfPossession, Typ, URL_NOT_VALID, WellKnownEndpoints } from '@sphereon/openid4vci-common';
import * as jose from 'jose';
import nock from 'nock';

import { CredentialRequestClientBuilder, IssuanceInitiation, MetadataClient } from '../lib';
import { ProofOfPossessionBuilder } from '../lib';

import { IDENTIPROOF_ISSUER_URL, IDENTIPROOF_OID4VCI_METADATA, INITIATION_TEST, WALT_OID4VCI_METADATA } from './MetadataMocks';

const partialJWT = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmN';

const jwt: Jwt = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: Typ.JWT },
  payload: { iss: 'sphereon:wallet', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL },
};

const kid = 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1';

let keypair: KeyPair;

async function proofOfPossessionCallbackFunction(args: Jwt, kid: string): Promise<string> {
  return await new jose.SignJWT({ ...args.payload })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt()
    .setIssuer(kid)
    .setAudience(args.payload.aud)
    .setExpirationTime('2h')
    .sign(keypair.privateKey);
}

interface KeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

beforeAll(async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256');
  keypair = { publicKey: publicKey as KeyObject, privateKey: privateKey as KeyObject };
});

beforeEach(async () => {
  nock.cleanAll();
  nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
});

describe('Credential Request Client ', () => {
  it('should get a failed credential response with an unsupported format', async function () {
    const basePath = 'https://sphereonjunit2022101301.com/';
    nock(basePath).post(/.*/).reply(200, {
      error: 'unsupported_format',
      error_description: 'This is a mock error message',
    });

    const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiation({ initiation: INITIATION_TEST })
      .withCredentialEndpoint(basePath + '/credential')
      .withFormat('ldp_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
    })
      // .withEndpointMetadata(metadata)
      .withClientId('sphereon:wallet')
      .withKid(kid)
      .build();
    expect(credReqClient.getCredentialEndpoint()).toEqual(basePath + '/credential');
    const credentialRequest: CredentialRequest = await credReqClient.createCredentialRequest({ proofInput: proof });
    expect(credentialRequest.proof.jwt.includes(partialJWT)).toBeTruthy();
    const result = await credReqClient.acquireCredentialsUsingRequest(credentialRequest);
    expect(result.successBody['error']).toBe('unsupported_format');
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
    const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiationRequest({ request: INITIATION_TEST.issuanceInitiationRequest })
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
    })
      // .withEndpointMetadata(metadata)
      .withKid(kid)
      .withClientId('sphereon:wallet')
      .build();
    const credentialRequest: CredentialRequest = await credReqClient.createCredentialRequest({ proofInput: proof, format: 'jwt' });
    expect(credentialRequest.proof.jwt.includes(partialJWT)).toBeTruthy();
    expect(credentialRequest.format).toEqual('jwt');
    const result = await credReqClient.acquireCredentialsUsingRequest(credentialRequest);
    expect(result.successBody['credential']).toEqual(mockedVC);
  });

  it('should fail with invalid url', async () => {
    const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiationRequest({ request: INITIATION_TEST.issuanceInitiationRequest })
      .withCredentialEndpoint('httpsf://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
    })
      // .withEndpointMetadata(metadata)
      .withKid(kid)
      .withClientId('sphereon:wallet')
      .build();
    await expect(credReqClient.acquireCredentialsUsingRequest({ format: 'jwt_vc', type: 'random', proof })).rejects.toThrow(Error(URL_NOT_VALID));
  });
});

describe('Credential Request Client with Walt.id ', () => {
  it('should have correct metadata endpoints', async function () {
    nock.cleanAll();
    const WALT_IRR_URI =
      'openid-initiate-issuance://?issuer=https%3A%2F%2Fjff.walt.id%2Fissuer-api%2Foidc%2F&credential_type=OpenBadgeCredential&pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE&user_pin_required=false';
    const initiation = IssuanceInitiation.fromURI(WALT_IRR_URI);

    const metadata = await MetadataClient.retrieveAllMetadataFromInitiation(initiation);
    expect(metadata.credential_endpoint).toEqual(WALT_OID4VCI_METADATA.credential_endpoint);
    expect(metadata.token_endpoint).toEqual(WALT_OID4VCI_METADATA.token_endpoint);

    const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiation({
      initiation,
      metadata,
    }).build();
    expect(credReqClient._issuanceRequestOpts.credentialEndpoint).toBe(WALT_OID4VCI_METADATA.credential_endpoint);
  });
});
