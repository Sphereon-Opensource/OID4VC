import { KeyObject } from 'crypto';

import { Alg, JWS_NOT_VALID, Jwt, NO_JWT_PROVIDED, OpenId4VCIVersion, PROOF_CANT_BE_CONSTRUCTED, ProofOfPossession } from '@sphereon/oid4vci-common';
import * as jose from 'jose';

import { ProofOfPossessionBuilder } from '..';

import { IDENTIPROOF_ISSUER_URL } from './MetadataMocks';

const jwt: Jwt = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: 'jwt' },
  payload: { iss: 'sphereon:wallet', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL, iat: Date.now() },
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
    .setIssuedAt(args.payload.iat)
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

describe('ProofOfPossession Builder ', () => {
  it('should fail without supplied proof or callbacks', async function () {
    await expect(
      ProofOfPossessionBuilder.fromProof(undefined as never, OpenId4VCIVersion.VER_1_0_11)
        .withIssuer(IDENTIPROOF_ISSUER_URL)
        .withClientId('sphereon:wallet')
        .withKid(kid)
        .build(),
    ).rejects.toThrow(Error(PROOF_CANT_BE_CONSTRUCTED));
  });

  it('should fail wit undefined jwt supplied', async function () {
    await expect(() =>
      ProofOfPossessionBuilder.fromJwt({ jwt, callbacks: { signCallback: proofOfPossessionCallbackFunction }, version: OpenId4VCIVersion.VER_1_0_08 })
        .withJwt(undefined as never)
        .withIssuer(IDENTIPROOF_ISSUER_URL)
        .withClientId('sphereon:wallet')
        .withKid(kid)
        .build(),
    ).toThrow(Error(NO_JWT_PROVIDED));
  });

  it('should build a proof with all required params present', async function () {
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
      version: OpenId4VCIVersion.VER_1_0_08,
    })
      .withIssuer(IDENTIPROOF_ISSUER_URL)
      .withKid(kid)
      .withClientId('sphereon:wallet')
      .build();
    expect(proof).toBeDefined();
  });

  it('should fail creating a proof of possession with simple verification', async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async function proofOfPossessionCallbackFunction(_args: Jwt, _kid?: string): Promise<string> {
      throw new Error(JWS_NOT_VALID);
    }

    await expect(
      ProofOfPossessionBuilder.fromJwt({ jwt, callbacks: { signCallback: proofOfPossessionCallbackFunction }, version: OpenId4VCIVersion.VER_1_0_08 })
        .withIssuer(IDENTIPROOF_ISSUER_URL)
        .withClientId('sphereon:wallet')
        .withKid(kid)
        .build(),
    ).rejects.toThrow(Error(JWS_NOT_VALID));
  });

  it('should fail creating a proof of possession without verify callback', async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async function proofOfPossessionCallbackFunction(_args: Jwt, _kid?: string): Promise<string> {
      throw new Error(JWS_NOT_VALID);
    }

    await expect(
      ProofOfPossessionBuilder.fromJwt({ jwt, callbacks: { signCallback: proofOfPossessionCallbackFunction }, version: OpenId4VCIVersion.VER_1_0_08 })
        .withIssuer(IDENTIPROOF_ISSUER_URL)
        .withClientId('sphereon:wallet')
        .withKid(kid)
        .build(),
    ).rejects.toThrow(Error(JWS_NOT_VALID));
  });
});
