import { KeyObject } from 'crypto';

import * as jose from 'jose';
import nock from 'nock';

import {
  Alg,
  EndpointMetadata,
  JWS_NOT_VALID,
  Jwt,
  MetadataClient,
  NO_JWT_PROVIDED,
  PROOF_CANT_BE_CONSTRUCTED,
  ProofOfPossession,
  Typ,
  WellKnownEndpoints,
} from '../lib';
import { ProofOfPossessionBuilder } from '../lib/ProofOfPossessionBuilder';

import { IDENTIPROOF_ISSUER_URL, IDENTIPROOF_OID4VCI_METADATA } from './MetadataMocks';

// const partialJWT = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmN';

const jwt: Jwt = {
  header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: Typ.JWT },
  payload: { iss: 'sphereon:wallet', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL },
};

const kid = 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1';

let keypair: KeyPair;
let metadata: EndpointMetadata;

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
  nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA));
  metadata = await MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL);
});

describe('ProofOfPossession Builder ', () => {
  it('should fail without supplied proof or callbacks', async function () {
    await expect(
      ProofOfPossessionBuilder.fromProof(undefined as never)
        .withEndpointMetadata(metadata)
        .withClientId('sphereon:wallet')
        .withKid(kid)
        .build()
    ).rejects.toThrow(Error(PROOF_CANT_BE_CONSTRUCTED));
  });

  it('should fail wit undefined jwt supplied', async function () {
    await expect(() =>
      ProofOfPossessionBuilder.fromJwt({ jwt, callbacks: { signCallback: proofOfPossessionCallbackFunction } })
        .withJwt(undefined)
        .withEndpointMetadata(metadata)
        .withClientId('sphereon:wallet')
        .withKid(kid)
        .build()
    ).toThrow(Error(NO_JWT_PROVIDED));
  });

  it('should build a proof with all required params present', async function () {
    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
    })
      .withEndpointMetadata(metadata)
      .withKid(kid)
      .withClientId('sphereon:wallet')
      .build();
    expect(proof).toBeDefined();
  });

  it('should fail creating a proof of possession with simple verification', async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async function proofOfPossessionCallbackFunction(_args: Jwt, _kid: string): Promise<string> {
      throw new Error(JWS_NOT_VALID);
    }

    await expect(
      ProofOfPossessionBuilder.fromJwt({ jwt, callbacks: { signCallback: proofOfPossessionCallbackFunction } })
        .withEndpointMetadata(metadata)
        .withClientId('sphereon:wallet')
        .withKid(kid)
        .build()
    ).rejects.toThrow(Error(JWS_NOT_VALID));
  });

  it('should fail creating a proof of possession without verify callback', async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    async function proofOfPossessionCallbackFunction(_args: Jwt, _kid: string): Promise<string> {
      throw new Error(JWS_NOT_VALID);
    }

    await expect(
      ProofOfPossessionBuilder.fromJwt({ jwt, callbacks: { signCallback: proofOfPossessionCallbackFunction } })
        .withEndpointMetadata(metadata)
        .withClientId('sphereon:wallet')
        .withKid(kid)
        .build()
    ).rejects.toThrow(Error(JWS_NOT_VALID));
  });
});
