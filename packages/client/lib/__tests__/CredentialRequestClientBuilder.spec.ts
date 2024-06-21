import { KeyObject } from 'crypto';

import {
  Alg,
  CredentialIssuerMetadataV1_0_13,
  CredentialRequestV1_0_13,
  Jwt,
  JwtVerifyResult,
  OpenId4VCIVersion,
  ProofOfPossession,
} from '@sphereon/oid4vci-common';
import * as jose from 'jose';

import { CredentialRequestClientBuilderV1_0_13, ProofOfPossessionBuilder } from '..';
import { CredentialRequestClientBuilder } from '../CredentialRequestClientBuilder';

import { IDENTIPROOF_ISSUER_URL, IDENTIPROOF_OID4VCI_METADATA, INITIATION_TEST_URI, WALT_ISSUER_URL, WALT_OID4VCI_METADATA } from './MetadataMocks';

const partialJWT = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmN';
const partialJWT_withoutDid = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJlYmZlYjFmNzEyZWJjNmYxYzI3N';

/*const jwtv1_0_08: Jwt = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: 'jwt' },
  payload: { iss: 'sphereon:wallet', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL },
};*/

const jwtv1_0_11: Jwt = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: 'openid4vci-proof+jwt' },
  payload: { iss: 'sphereon:wallet', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL },
};

const jwtv1_0_13_withoutDid: Jwt = {
  header: { alg: Alg.ES256, kid: 'ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: 'openid4vci-proof+jwt' },
  payload: { iss: 'sphereon:wallet', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL },
};

const kid = 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1';

const kid_withoutDid = 'ebfeb1f712ebc6f1c276e12ec21/keys/1';

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

async function proofOfPossessionVerifierCallbackFunction(args: { jwt: string; kid?: string }): Promise<JwtVerifyResult<unknown>> {
  const result = await jose.jwtVerify(args.jwt, keypair.publicKey);
  const kid = result.protectedHeader.kid ?? args.kid;
  const did = kid!.split('#')[0];
  const didDocument = {};
  const alg = result.protectedHeader.alg;
  return {
    alg,
    did,
    kid,
    didDocument,
    jwt: { header: result.protectedHeader, payload: result.payload },
  };
}

describe('Credential Request Client Builder', () => {
  it('should build correctly provided with correct params', async function () {
    const credReqClient = ((await CredentialRequestClientBuilder.fromURI({ uri: INITIATION_TEST_URI })) as CredentialRequestClientBuilderV1_0_13)
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialIdentifier('credentialType')
      .withToken('token')
      .build();
    expect(credReqClient.credentialRequestOpts.credentialEndpoint).toBe('https://oidc4vci.demo.spruceid.com/credential');
    expect(credReqClient.credentialRequestOpts.format).toBe('jwt_vc');
    expect(credReqClient.credentialRequestOpts.credentialIdentifier).toStrictEqual('credentialType');
    expect(credReqClient.credentialRequestOpts.token).toBe('token');
  });

  it('should build credential request correctly', async () => {
    const credReqClient = ((await CredentialRequestClientBuilder.fromURI({ uri: INITIATION_TEST_URI })) as CredentialRequestClientBuilderV1_0_13)
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialIdentifier('OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt: jwtv1_0_11,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
        verifyCallback: proofOfPossessionVerifierCallbackFunction,
      },
      version: OpenId4VCIVersion.VER_1_0_13,
    })
      .withClientId('sphereon:wallet')
      .withKid(kid)
      .build();
    await proofOfPossessionVerifierCallbackFunction({ ...proof, kid });
    const credentialRequest: CredentialRequestV1_0_13 = await credReqClient.createCredentialRequest({
      proofInput: proof,
      credentialIdentifier: 'OpenBadgeCredential',
      version: OpenId4VCIVersion.VER_1_0_13,
    });
    expect(credentialRequest.proof?.jwt).toContain(partialJWT);
    expect('credential_identifier' in credentialRequest).toBe(true);
    if ('types' in credentialRequest) {
      expect(credentialRequest.types).toStrictEqual(['https://imsglobal.github.io/openbadges-specification/ob_v3p0.html#OpenBadgeCredential']);
    }
  });

  it('should build credential request correctly without did', async () => {
    const credReqClient = (await CredentialRequestClientBuilder.fromURI({ uri: INITIATION_TEST_URI }))
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc')
      .withCredentialType('OpenBadgeCredential')
      .build();
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt: jwtv1_0_13_withoutDid,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
        verifyCallback: proofOfPossessionVerifierCallbackFunction,
      },
      version: OpenId4VCIVersion.VER_1_0_13,
    })
      .withClientId('sphereon:wallet')
      .withKid(kid_withoutDid)
      .build();
    await proofOfPossessionVerifierCallbackFunction({ ...proof, kid: kid_withoutDid });
    const credentialRequest: CredentialRequestV1_0_13 = await credReqClient.createCredentialRequest({
      proofInput: proof,
      credentialTypes: 'OpenBadgeCredential',
      version: OpenId4VCIVersion.VER_1_0_13,
    });
    expect(credentialRequest.proof?.jwt).toContain(partialJWT_withoutDid);
    if ('types' in credentialRequest) {
      expect(credentialRequest.types).toStrictEqual(['OpenBadgeCredential']);
    }
  });

  it('should build correctly from metadata', async () => {
    const credReqClient = (
      await CredentialRequestClientBuilder.fromURI({
        uri: INITIATION_TEST_URI,
        metadata: WALT_OID4VCI_METADATA,
      })
    )
      .withFormat('jwt_vc')
      .build();
    expect(credReqClient.credentialRequestOpts.credentialEndpoint).toBe(`${WALT_ISSUER_URL}/credential`);
  });

  it('should build correctly with endpoint from metadata', async () => {
    const credReqClient = (await CredentialRequestClientBuilder.fromURI({ uri: INITIATION_TEST_URI }))
      .withFormat('jwt_vc')
      .withCredentialEndpointFromMetadata(IDENTIPROOF_OID4VCI_METADATA as unknown as CredentialIssuerMetadataV1_0_13)
      .build();
    expect(credReqClient.credentialRequestOpts.credentialEndpoint).toBe(`${IDENTIPROOF_ISSUER_URL}/credential`);
  });
});
