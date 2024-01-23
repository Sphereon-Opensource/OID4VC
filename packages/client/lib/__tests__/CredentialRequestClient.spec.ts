import { KeyObject } from 'crypto';

import {
  Alg,
  EndpointMetadata,
  getCredentialRequestForVersion,
  getIssuerFromCredentialOfferPayload,
  Jwt,
  OpenId4VCIVersion,
  ProofOfPossession,
  URL_NOT_VALID,
  WellKnownEndpoints,
} from '@sphereon/oid4vci-common';
import * as jose from 'jose';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock';

import { CredentialRequestClientBuilder, MetadataClient, ProofOfPossessionBuilder } from '..';
import { CredentialOfferClient } from '../CredentialOfferClient';

import { IDENTIPROOF_ISSUER_URL, IDENTIPROOF_OID4VCI_METADATA, INITIATION_TEST, WALT_OID4VCI_METADATA } from './MetadataMocks';
import { getMockData } from './data/VciDataFixtures';

const partialJWT = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmN';

const jwt: Jwt = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: 'jwt' },
  payload: { iss: 'sphereon:wallet', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL },
};

const kid = 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1';

let keypair: KeyPair;

async function proofOfPossessionCallbackFunction(args: Jwt, kid?: string): Promise<string> {
  if (!args.payload.aud) {
    throw Error('aud required');
  } else if (!kid) {
    throw Error('kid required');
  }
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

afterEach(async () => {
  nock.cleanAll();
});
describe('Credential Request Client ', () => {
  it('should get a failed credential response with an unsupported format', async function () {
    const basePath = 'https://sphereonjunit2022101301.com/';
    nock(basePath).post(/.*/).reply(500, {
      error: 'unsupported_format',
      error_description: 'This is a mock error message',
    });

    const credReqClient = CredentialRequestClientBuilder.fromCredentialOffer({ credentialOffer: INITIATION_TEST })
      .withCredentialEndpoint(basePath + '/credential')
      .withFormat('ldp_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
      version: OpenId4VCIVersion.VER_1_0_08,
    })
      // .withEndpointMetadata(metadata)
      .withClientId('sphereon:wallet')
      .withKid(kid)
      .build();
    expect(credReqClient.getCredentialEndpoint()).toEqual(basePath + '/credential');
    const credentialRequest = await credReqClient.createCredentialRequest({ proofInput: proof, version: OpenId4VCIVersion.VER_1_0_08 });
    expect(credentialRequest.proof?.jwt?.includes(partialJWT)).toBeTruthy();
    const result = await credReqClient.acquireCredentialsUsingRequest(credentialRequest);
    expect(result?.errorBody?.error).toBe('unsupported_format');
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
    const credReqClient = CredentialRequestClientBuilder.fromCredentialOfferRequest({ request: INITIATION_TEST })
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
      version: OpenId4VCIVersion.VER_1_0_08,
    })
      // .withEndpointMetadata(metadata)
      .withKid(kid)
      .withClientId('sphereon:wallet')
      .build();
    const credentialRequest = await credReqClient.createCredentialRequest({
      proofInput: proof,
      format: 'jwt',
      version: OpenId4VCIVersion.VER_1_0_08,
    });
    expect(credentialRequest.proof?.jwt?.includes(partialJWT)).toBeTruthy();
    expect(credentialRequest.format).toEqual('jwt_vc');
    const result = await credReqClient.acquireCredentialsUsingRequest(credentialRequest);
    expect(result?.successBody?.credential).toEqual(mockedVC);
  });

  it('should fail with invalid url', async () => {
    const credReqClient = CredentialRequestClientBuilder.fromCredentialOfferRequest({ request: INITIATION_TEST })
      .withCredentialEndpoint('httpsf://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
      version: OpenId4VCIVersion.VER_1_0_08,
    })
      // .withEndpointMetadata(metadata)
      .withKid(kid)
      .withClientId('sphereon:wallet')
      .build();
    await expect(credReqClient.acquireCredentialsUsingRequest({ format: 'jwt_vc_json', types: ['random'], proof })).rejects.toThrow(
      Error(URL_NOT_VALID),
    );
  });
});

describe('Credential Request Client with Walt.id ', () => {
  beforeEach(() => {
    nock.cleanAll();
  });

  afterEach(() => {
    nock.cleanAll();
  });
  it('should have correct metadata endpoints', async function () {
    nock.cleanAll();
    const WALT_IRR_URI =
      'openid-initiate-issuance://?issuer=https%3A%2F%2Fjff.walt.id%2Fissuer-api%2Foidc%2F&credential_type=OpenBadgeCredential&pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE&user_pin_required=false';
    const credentialOffer = await CredentialOfferClient.fromURI(WALT_IRR_URI);

    const request = credentialOffer.credential_offer;
    const metadata = await MetadataClient.retrieveAllMetadata(getIssuerFromCredentialOfferPayload(request) as string);
    expect(metadata.credential_endpoint).toEqual(WALT_OID4VCI_METADATA.credential_endpoint);
    expect(metadata.token_endpoint).toEqual(WALT_OID4VCI_METADATA.token_endpoint);

    const credReqClient = CredentialRequestClientBuilder.fromCredentialOffer({
      credentialOffer,
      metadata,
    }).build();
    expect(credReqClient.credentialRequestOpts.credentialEndpoint).toBe(WALT_OID4VCI_METADATA.credential_endpoint);
  });
});

describe('Credential Request Client with different issuers ', () => {
  beforeEach(() => {
    nock.cleanAll();
  });

  afterEach(() => {
    nock.cleanAll();
  });
  it('should create correct CredentialRequest for Spruce', async () => {
    const IRR_URI =
      'openid-initiate-issuance://?issuer=https%3A%2F%2Fngi%2Doidc4vci%2Dtest%2Espruceid%2Exyz&credential_type=OpenBadgeCredential&pre-authorized_code=eyJhbGciOiJFUzI1NiJ9.eyJjcmVkZW50aWFsX3R5cGUiOlsiT3BlbkJhZGdlQ3JlZGVudGlhbCJdLCJleHAiOiIyMDIzLTA0LTIwVDA5OjA0OjM2WiIsIm5vbmNlIjoibWFibmVpT0VSZVB3V3BuRFFweEt3UnRsVVRFRlhGUEwifQ.qOZRPN8sTv_knhp7WaWte2-aDULaPZX--2i9unF6QDQNUllqDhvxgIHMDCYHCV8O2_Gj-T2x1J84fDMajE3asg&user_pin_required=false';
    const credentialRequest = await (
      await CredentialRequestClientBuilder.fromURI({
        uri: IRR_URI,
        metadata: getMockData('spruce')?.metadata as unknown as EndpointMetadata,
      })
    )
      .build()
      .createCredentialRequest({
        proofInput: {
          proof_type: 'jwt',
          jwt: getMockData('spruce')?.credential.request.proof.jwt as string,
        },
        credentialTypes: ['OpenBadgeCredential'],
        format: 'jwt_vc',
        version: OpenId4VCIVersion.VER_1_0_08,
      });
    const draft8CredentialRequest = getCredentialRequestForVersion(credentialRequest, OpenId4VCIVersion.VER_1_0_08);
    expect(draft8CredentialRequest).toEqual(getMockData('spruce')?.credential.request);
  });

  it('should create correct CredentialRequest for Walt', async () => {
    nock.cleanAll();
    const IRR_URI =
      'openid-initiate-issuance://?issuer=https%3A%2F%2Fjff.walt.id%2Fissuer-api%2Fdefault%2Foidc%2F&credential_type=OpenBadgeCredential&pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIwMTc4OTNjYy04ZTY3LTQxNzItYWZlOS1lODcyYmYxNDBlNWMiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.ODfq2AIhOcB61dAb3zMrXBJjPJaf53zkeHh_AssYyYA&user_pin_required=false';
    const credentialOffer = await (
      await CredentialRequestClientBuilder.fromURI({
        uri: IRR_URI,
        metadata: getMockData('walt')?.metadata as unknown as EndpointMetadata,
      })
    )
      .build()
      .createCredentialRequest({
        proofInput: {
          proof_type: 'jwt',
          jwt: getMockData('walt')?.credential.request.proof.jwt as string,
        },
        credentialTypes: ['OpenBadgeCredential'],
        format: 'jwt_vc',
        version: OpenId4VCIVersion.VER_1_0_08,
      });
    expect(credentialOffer).toEqual(getMockData('walt')?.credential.request);
  });

  // Missing the issuer required property
  xit('should create correct CredentialRequest for uniissuer', async () => {
    const IRR_URI =
      'https://oidc4vc.uniissuer.io/?credential_type=OpenBadgeCredential&pre-authorized_code=0ApoI8rxVmdQ44RIpuDbFIURIIkOhyek&user_pin_required=false';
    const credentialOffer = await (
      await CredentialRequestClientBuilder.fromURI({
        uri: IRR_URI,
        metadata: getMockData('uniissuer')?.metadata as unknown as EndpointMetadata,
      })
    )
      .build()
      .createCredentialRequest({
        proofInput: {
          proof_type: 'jwt',
          jwt: getMockData('uniissuer')?.credential.request.proof.jwt as string,
        },
        credentialTypes: ['OpenBadgeCredential'],
        format: 'jwt_vc',
        version: OpenId4VCIVersion.VER_1_0_08,
      });
    expect(credentialOffer).toEqual(getMockData('uniissuer')?.credential.request);
  });

  it('should create correct CredentialRequest for mattr', async () => {
    const IRR_URI =
      'openid-initiate-issuance://?issuer=https://launchpad.mattrlabs.com&credential_type=OpenBadgeCredential&pre-authorized_code=g0UCOj6RAN5AwHU6gczm_GzB4_lH6GW39Z0Dl2DOOiO';
    const credentialOffer = await (
      await CredentialRequestClientBuilder.fromURI({
        uri: IRR_URI,
        metadata: getMockData('mattr')?.metadata as unknown as EndpointMetadata,
      })
    )
      .build()
      .createCredentialRequest({
        proofInput: {
          proof_type: 'jwt',
          jwt: getMockData('mattr')?.credential.request.proof.jwt as string,
        },
        credentialTypes: ['OpenBadgeCredential'],
        format: 'ldp_vc',
        version: OpenId4VCIVersion.VER_1_0_08,
      });
    const credentialRequest = getCredentialRequestForVersion(credentialOffer, OpenId4VCIVersion.VER_1_0_08);
    expect(credentialRequest).toEqual(getMockData('mattr')?.credential.request);
  });

  it('should create correct CredentialRequest for diwala', async () => {
    const IRR_URI =
      'openid-initiate-issuance://?issuer=https://oidc4vc.diwala.io&credential_type=OpenBadgeCredential&pre-authorized_code=eyJhbGciOiJIUzI1NiJ9.eyJjcmVkZW50aWFsX3R5cGUiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZXhwIjoxNjgxOTg0NDY3fQ.fEAHKz2nuWfiYHw406iNxr-81pWkNkbi31bWsYSf6Ng';
    const credentialOffer = await (
      await CredentialRequestClientBuilder.fromURI({
        uri: IRR_URI,
        metadata: getMockData('diwala')?.metadata as unknown as EndpointMetadata,
      })
    )
      .build()
      .createCredentialRequest({
        proofInput: {
          proof_type: 'jwt',
          jwt: getMockData('diwala')?.credential.request.proof.jwt as string,
        },
        credentialTypes: ['OpenBadgeCredential'],
        format: 'ldp_vc',
        version: OpenId4VCIVersion.VER_1_0_08,
      });

    // createCredentialRequest returns uniform format in draft 11
    const credentialRequest = getCredentialRequestForVersion(credentialOffer, OpenId4VCIVersion.VER_1_0_08);

    expect(credentialRequest).toEqual(getMockData('diwala')?.credential.request);
  });
});
