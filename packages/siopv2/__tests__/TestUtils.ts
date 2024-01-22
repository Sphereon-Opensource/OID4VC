import crypto from 'crypto';

import { IProofType } from '@sphereon/ssi-types';
import base58 from 'bs58';
import { DIDDocument } from 'did-resolver';
import { ethers } from 'ethers';
import { exportJWK, importJWK, JWK, JWTPayload, SignJWT } from 'jose';
import jwt_decode from 'jwt-decode';
import moment from 'moment';
import { v4 as uuidv4 } from 'uuid';

import { ResponseType } from '../../common/lib';
import {
  assertValidMetadata,
  base64ToHexString,
  DiscoveryMetadataPayload,
  KeyCurve,
  KeyType,
  ResponseIss,
  RPRegistrationMetadataPayload,
  Scope,
  SigningAlgo,
  SubjectSyntaxTypesSupportedValues,
  SubjectType,
} from '../src';
import SIOPErrors from '../src/types/Errors';

import {
  DID_DOCUMENT_PUBKEY_B58,
  DID_DOCUMENT_PUBKEY_JWK,
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData';

export interface TESTKEY {
  key: JWK;
  did: string;
  didDoc?: DIDDocument;
}

export async function generateTestKey(kty: string): Promise<TESTKEY> {
  if (kty !== KeyType.EC) throw new Error(SIOPErrors.NO_ALG_SUPPORTED);
  const key = crypto.generateKeyPairSync('ec', {
    namedCurve: KeyCurve.SECP256k1,
  });
  const privateJwk = await exportJWK(key.privateKey);

  const did = getDIDFromKey(privateJwk);

  return {
    key: privateJwk,
    did,
  };
}

function getDIDFromKey(key: JWK): string {
  return `did:ethr:${getEthAddress(key)}`;
}

function getEthAddress(key: JWK): string {
  return getEthWallet(key).address;
}

function getEthWallet(key: JWK): ethers.Wallet {
  return new ethers.Wallet(prefixWith0x(base64ToHexString(key.d)));
}

export const prefixWith0x = (key: string): string => (key.startsWith('0x') ? key : `0x${key}`);

export interface IEnterpriseAuthZToken extends JWTPayload {
  sub?: string;
  did: string;
  aud: string;
  nonce: string;
}

export interface LegalEntityTestAuthN {
  iss: string; // legal entity name identifier
  aud: string; // RP Application Name.
  iat: number;
  exp: number;
  nonce: string;
  callbackUrl?: string; // Entity url to send notifications
  image?: string; // base64 encoded image data
  icon?: string; // base64 encoded image icon data
}

export const mockedKeyAndDid = async (): Promise<{
  hexPrivateKey: string;
  did: string;
  jwk: JWK;
  hexPublicKey: string;
}> => {
  // generate a new keypair
  const key = crypto.generateKeyPairSync('ec', {
    namedCurve: KeyCurve.SECP256k1,
  });
  const privateJwk = await exportJWK(key.privateKey);
  const hexPrivateKey = base64ToHexString(privateJwk.d);
  const wallet: ethers.Wallet = new ethers.Wallet(prefixWith0x(hexPrivateKey));
  const did = `did:ethr:${wallet.address}`;
  const hexPublicKey = wallet.signingKey.publicKey;

  return {
    hexPrivateKey,
    did,
    jwk: privateJwk,
    hexPublicKey,
  };
};

const mockedEntityAuthNToken = async (
  enterpiseName?: string,
): Promise<{
  jwt: string;
  jwk: JWK;
  did: string;
  hexPrivateKey: string;
  hexPublicKey: string;
}> => {
  // generate a new keypair
  const { did, jwk, hexPrivateKey, hexPublicKey } = await mockedKeyAndDid();

  const payload: LegalEntityTestAuthN = {
    iss: enterpiseName || 'Test Entity',
    aud: 'test',
    iat: moment().unix(),
    exp: moment().add(15, 'minutes').unix(),
    nonce: uuidv4(),
  };

  const privateKey = await importJWK(jwk, SigningAlgo.ES256K);
  const jwt = await new SignJWT(payload as unknown as JWTPayload)
    .setProtectedHeader({
      alg: 'ES256K',
      typ: 'JWT',
    })
    .sign(privateKey);
  return { jwt, jwk, did, hexPrivateKey, hexPublicKey };
};

export async function mockedGetEnterpriseAuthToken(enterpriseName?: string): Promise<{
  jwt: string;
  did: string;
  jwk: JWK;
  hexPrivateKey: string;
  hexPublicKey: string;
}> {
  const testAuth = await mockedEntityAuthNToken(enterpriseName);
  const payload = jwt_decode(testAuth.jwt);

  const inputPayload: IEnterpriseAuthZToken = {
    did: testAuth.did,

    aud: (payload as JWTPayload)?.iss ? (payload as JWTPayload).iss : 'Test Entity',
    nonce: (payload as IEnterpriseAuthZToken).nonce,
  };

  const testApiPayload = {
    ...inputPayload,
    ...{
      sub: (payload as JWTPayload).iss, // Should be the id of the app that is requesting the token
      iat: moment().unix(),
      exp: moment().add(15, 'minutes').unix(),
      aud: 'test',
    },
  };

  const privateKey = await importJWK(testAuth.jwk, SigningAlgo.ES256K);
  const jwt = await new SignJWT(testApiPayload)
    .setProtectedHeader({
      alg: 'ES256K',
      typ: 'JWT',
    })
    .sign(privateKey);

  return {
    jwt,
    did: testAuth.did,
    jwk: testAuth.jwk,
    hexPrivateKey: testAuth.hexPrivateKey,
    hexPublicKey: testAuth.hexPublicKey,
  };
}

export interface DidKey {
  did: string;
  publicKeyHex?: string;
  jwk?: JWK;
}

interface FixJwk extends JWK {
  kty: string;
}

export const getParsedDidDocument = (didKey: DidKey): DIDDocument => {
  if (didKey.publicKeyHex) {
    const didDocB58 = DID_DOCUMENT_PUBKEY_B58;
    didDocB58.id = didKey.did;
    didDocB58.controller = didKey.did;
    didDocB58.verificationMethod[0].id = `${didKey.did}#keys-1`;
    didDocB58.verificationMethod[0].controller = didKey.did;
    didDocB58.verificationMethod[0].publicKeyBase58 = base58.encode(Buffer.from(didKey.publicKeyHex.replace('0x', ''), 'hex'));
    return didDocB58;
  }
  // then didKey jws public key
  const didDocJwk = DID_DOCUMENT_PUBKEY_JWK;
  const { jwk } = didKey;
  jwk.kty = didKey.jwk.kty || 'EC';
  didDocJwk.id = didKey.did;
  didDocJwk.controller = didKey.did;
  didDocJwk.verificationMethod[0].id = `${didKey.did}#keys-1`;
  didDocJwk.verificationMethod[0].controller = didKey.did;
  didDocJwk.verificationMethod[0].publicKeyJwk = jwk as FixJwk;
  return didDocJwk;
};

/*
export const resolveDidKey = async (did: string): Promise<DIDResolutionResult> => {
  return (await DidKeyDriver.get(did, {
    accept: 'application/did+ld+json',
  })) as DIDResolutionResult;
};
*/

export const WELL_KNOWN_OPENID_FEDERATION = 'https://www.example.com/.well-known/openid-federation';
export const metadata: {
  opMetadata: DiscoveryMetadataPayload;
  rpMetadata: RPRegistrationMetadataPayload;
  verify(): unknown;
} = {
  opMetadata: {
    issuer: ResponseIss.SELF_ISSUED_V2,
    authorization_endpoint: 'http://test.com',
    subject_syntax_types_supported: ['did:web'],
    id_token_signing_alg_values_supported: undefined,
    request_object_signing_alg_values_supported: [SigningAlgo.EDDSA],
    response_types_supported: ResponseType.ID_TOKEN,
    scopes_supported: [Scope.OPENID_DIDAUTHN],
    subject_types_supported: [SubjectType.PAIRWISE],
    vp_formats: {
      ldp_vc: {
        proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    },
    logo_uri: VERIFIER_LOGO_FOR_CLIENT + ' 2022-09-29 02',
    client_name: VERIFIER_NAME_FOR_CLIENT + ' 2022-09-29 02',
    'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + ' 2022-09-29 02',
    client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY + ' 2022-09-29 02',
    'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL + ' 2022-09-29 02',
  },
  rpMetadata: {
    client_id: WELL_KNOWN_OPENID_FEDERATION,
    id_token_signing_alg_values_supported: [],
    request_object_signing_alg_values_supported: [SigningAlgo.EDDSA],
    response_types_supported: [ResponseType.ID_TOKEN],
    scopes_supported: [Scope.OPENID, Scope.OPENID_DIDAUTHN],
    subject_syntax_types_supported: [SubjectSyntaxTypesSupportedValues.DID.valueOf(), 'did:web', 'did:key'],
    subject_types_supported: [SubjectType.PAIRWISE],
    vp_formats: {
      ldp_vc: {
        proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
      },
      jwt_vc: {
        alg: [SigningAlgo.ES256, SigningAlgo.ES256K],
      },
    },
    logo_uri: VERIFIER_LOGO_FOR_CLIENT + ' 2022-09-29 03',
    client_name: VERIFIER_NAME_FOR_CLIENT + ' 2022-09-29 03',
    'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + ' 2022-09-29 03',
    client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY + ' 2022-09-29 03',
    'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL + ' 2022-09-29 03',
  },
  verify() {
    return assertValidMetadata(this.opMetadata, this.rpMetadata);
  },
};
