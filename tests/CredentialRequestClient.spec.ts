import nock from 'nock';

import {
  CredentialRequest,
  CredentialRequestClient,
  CredentialRequestClientBuilder,
  CredentialResponse,
  ErrorResponse,
  IssuanceInitiation,
  JWS_NOT_VALID,
  MetadataClient,
  ProofOfPossession,
  ProofOfPossessionCallbackArgs,
} from '../lib';
import { ProofOfPossessionBuilder } from '../lib/ProofOfPossessionBuilder';

import { WALT_OID4VCI_METADATA } from './MetadataMocks';

// const partialJWT = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMS9rZXlzLzEifQ.eyJhdWQiOiJodHRwczovL29pZGM0dmNpLmRlbW8uc3BydWNlaWQuY29tL2NyZWRlbnRpYWwiLCJp';

async function proofOfPossessionCallbackFunction(_args: ProofOfPossessionCallbackArgs): Promise<string> {
  return 'ey.val.eu';
}

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
    const proof: ProofOfPossession = await new ProofOfPossessionBuilder()
      .withPoPCallbackOpts({
        proofOfPossessionCallback: proofOfPossessionCallbackFunction,
        proofOfPossessionCallbackArgs: {
          kid: 'did:example:123',
          payload: {
            aud: 'aud',
            iss: 'sphereon',
          },
        },
      })
      .build();
    const credentialRequest: CredentialRequest = await credReqClient.createCredentialRequest(proof);
    expect(credentialRequest.proof.jwt).toContain('ey.val.eu');
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
    const proof: ProofOfPossession = await new ProofOfPossessionBuilder()
      .withPoPCallbackOpts({
        proofOfPossessionCallback: proofOfPossessionCallbackFunction,
        proofOfPossessionCallbackArgs: {
          kid: 'did:example:123',
          payload: {
            aud: 'aud',
            iss: 'sphereon',
          },
        },
      })
      .build();
    const credentialRequest: CredentialRequest = await credReqClient.createCredentialRequest(proof);
    expect(credentialRequest.proof.jwt.includes('ey.val')).toBeTruthy();
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
    const proof: ProofOfPossession = await new ProofOfPossessionBuilder()
      .withPoPCallbackOpts({
        proofOfPossessionCallback: proofOfPossessionCallbackFunction,
        proofOfPossessionCallbackArgs: {
          kid: 'did:example:123',
          payload: {
            aud: 'aud',
            iss: 'sphereon',
          },
        },
      })
      .build();
    const credentialRequest: CredentialRequest = await credReqClient.createCredentialRequest(proof);
    expect(credentialRequest.proof.jwt.includes('ey.val')).toBeTruthy();
    const result: ErrorResponse | CredentialResponse = await credReqClient.acquireCredentialsUsingRequest(credentialRequest);
    expect(result['credential']).toEqual(mockedVC);
  });
  it('should fail creating a proof of possession with simple verification', async () => {
    async function proofOfPossessionCallbackFunction(_args: ProofOfPossessionCallbackArgs): Promise<string> {
      throw new Error(JWS_NOT_VALID);
    }
    await expect(
      new ProofOfPossessionBuilder()
        .withPoPCallbackOpts({
          proofOfPossessionCallback: proofOfPossessionCallbackFunction,
          proofOfPossessionCallbackArgs: {
            kid: 'did:example:123',
            payload: {
              aud: 'aud',
              iss: 'sphereon',
            },
          },
        })
        .build()
    ).rejects.toThrow(Error(JWS_NOT_VALID));
  });

  it('should fail creating a proof of possession with verify callback function', async () => {
    async function proofOfPossessionCallbackFunction(_args: ProofOfPossessionCallbackArgs): Promise<string> {
      throw new Error(JWS_NOT_VALID);
    }
    await expect(
      new ProofOfPossessionBuilder()
        .withPoPCallbackOpts({
          proofOfPossessionCallback: proofOfPossessionCallbackFunction,
          proofOfPossessionCallbackArgs: {
            kid: 'did:example:123',
            payload: {
              aud: 'aud value',
              iss: 'sphereon',
            },
          },
        })
        .build()
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
