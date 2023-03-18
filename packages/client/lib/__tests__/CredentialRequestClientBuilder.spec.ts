import { KeyObject } from 'crypto';

import { Alg, CredentialRequest, Jwt, OpenID4VCIServerMetadata, ProofOfPossession, Typ } from '@sphereon/openid4vci-common';
import * as jose from 'jose';

import { CredentialRequestClientBuilder, ProofOfPossessionBuilder } from '../lib';

import { IDENTIPROOF_ISSUER_URL, IDENTIPROOF_OID4VCI_METADATA, INITIATION_TEST_URI, WALT_ISSUER_URL, WALT_OID4VCI_METADATA } from './MetadataMocks';

const partialJWT = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmN';

const jwt: Jwt = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: Typ.JWT },
  payload: { iss: 'sphereon:wallet', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL },
};

const kid = 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1';

let keypair: KeyPair;

beforeAll(async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256');
  keypair = { publicKey: publicKey as KeyObject, privateKey: privateKey as KeyObject };
});

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

async function proofOfPossessionVerifierCallbackFunction(args: { jwt: string; kid?: string }): Promise<void> {
  await jose.compactVerify(args.jwt, keypair.publicKey);
}

describe('Credential Request Client Builder', () => {
  it('should build correctly provided with correct params', function () {
    const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiationURI({ uri: INITIATION_TEST_URI })
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('credentialType')
      .withToken('token')
      .build();
    expect(credReqClient.issuanceRequestOpts.credentialEndpoint).toBe('https://oidc4vci.demo.spruceid.com/credential');
    expect(credReqClient.issuanceRequestOpts.format).toBe('jwt_vc');
    expect(credReqClient.issuanceRequestOpts.credentialType).toBe('credentialType');
    expect(credReqClient.issuanceRequestOpts.token).toBe('token');
  });

  it('should build credential request correctly', async () => {
    const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiationURI({ uri: INITIATION_TEST_URI })
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
        verifyCallback: proofOfPossessionVerifierCallbackFunction,
      },
    })
      .withClientId('sphereon:wallet')
      .withKid(kid)
      .build();
    await proofOfPossessionVerifierCallbackFunction({ ...proof, kid });
    const credentialRequest: CredentialRequest = await credReqClient.createCredentialRequest({ proofInput: proof });
    expect(credentialRequest.proof.jwt).toContain(partialJWT);
    expect(credentialRequest.type).toBe('https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential');
  });

  it('should build correctly from metadata', async () => {
    const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiationURI({ uri: INITIATION_TEST_URI, metadata: WALT_OID4VCI_METADATA })
      .withFormat('jwt_vc')
      .build();
    expect(credReqClient.issuanceRequestOpts.credentialEndpoint).toBe(`${WALT_ISSUER_URL}/credential`);
  });

  it('should build correctly with endpoint from metadata', async () => {
    const credReqClient = CredentialRequestClientBuilder.fromIssuanceInitiationURI({ uri: INITIATION_TEST_URI })
      .withFormat('jwt_vc')
      .withCredentialEndpointFromMetadata(IDENTIPROOF_OID4VCI_METADATA as unknown as OpenID4VCIServerMetadata)
      .build();
    expect(credReqClient.issuanceRequestOpts.credentialEndpoint).toBe(`${IDENTIPROOF_ISSUER_URL}/credential`);
  });
});
