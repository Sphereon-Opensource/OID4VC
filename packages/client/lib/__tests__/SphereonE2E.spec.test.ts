import * as crypto from 'crypto';

import { Alg, Jwt, ProofOfPossessionCallbacks } from '@sphereon/oid4vci-common';
import { CredentialMapper } from '@sphereon/ssi-types';
import * as didts from '@transmute/did-key.js';
import { fetch } from 'cross-fetch';
import debug from 'debug';
import { importJWK, JWK, SignJWT } from 'jose';
import { v4 } from 'uuid';

import { OpenID4VCIClient } from '..';

export const UNIT_TEST_TIMEOUT = 60000;

const ISSUER_URL = 'https://ssi.sphereon.com/pf3';

const jwk: JWK = {
  crv: 'Ed25519',
  d: 'kTRm0aONHYwNPA-w_DtjMHUIWjE3K70qgCIhWojZ0eU',
  x: 'NeA0d8sp86xRh3DczU4m5wPNIbl0HCSwOBcMN3sNmdk',
  kty: 'OKP',
};

// pub  hex: 35e03477cb29f3ac518770dccd4e26e703cd21b9741c24b038170c377b0d99d9
// priv hex: 913466d1a38d1d8c0d3c0fb0fc3b633075085a31372bbd2a8022215a88d9d1e5
const did = `did:key:z6Mki5ZwZKN1dBQprfJTikUvkDxrHijiiQngkWviMF5gw2Hv`;
const kid = `${did}#z6Mki5ZwZKN1dBQprfJTikUvkDxrHijiiQngkWviMF5gw2Hv`;
describe('OID4VCI-Client using Sphereon issuer should', () => {
  async function test(format: 'ldp_vc' | 'jwt_vc_json') {
    debug.enable('*');
    const offer = await getCredentialOffer(format);
    const client = await OpenID4VCIClient.fromURI({
      uri: offer.uri,
      kid,
      alg: Alg.EdDSA,
    });
    expect(client.credentialOffer).toBeDefined();
    expect(client.endpointMetadata).toBeDefined();
    expect(client.getCredentialEndpoint()).toEqual(`${ISSUER_URL}/credentials`);
    expect(client.getAccessTokenEndpoint()).toEqual(`${ISSUER_URL}/token`);

    const accessToken = await client.acquireAccessToken();
    // console.log(accessToken);
    expect(accessToken).toMatchObject({
      expires_in: 300,
      // scope: 'GuestCredential',
      token_type: 'bearer',
    });

    const credentialResponse = await client.acquireCredentials({
      credentialTypes: 'GuestCredential',
      format,
      proofCallbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
    });
    expect(credentialResponse.credential).toBeDefined();
    const wrappedVC = CredentialMapper.toWrappedVerifiableCredential(credentialResponse.credential!);
    expect(format.startsWith(wrappedVC.format)).toEqual(true);
  }

  xit(
    'succeed in a full flow with the client using OpenID4VCI version 11 and ldp_vc',
    async () => {
      await test('ldp_vc');
    },
    UNIT_TEST_TIMEOUT,
  );
  xit(
    'succeed in a full flow with the client using OpenID4VCI version 11 and jwt_vc_json',
    async () => {
      await test('jwt_vc_json');
    },
    UNIT_TEST_TIMEOUT,
  );
});

interface CreateCredentialOfferResponse {
  uri: string;
  userPinRequired: boolean;
}

async function getCredentialOffer(format: 'ldp_vc' | 'jwt_vc_json'): Promise<CreateCredentialOfferResponse> {
  const credentialOffer = await fetch('https://ssi.sphereon.com/pf3/webapp/credential-offers', {
    method: 'post',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },

    //make sure to serialize your JSON body
    body: JSON.stringify({
      credentials: ['GuestCredential'],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': v4().substring(0, 10),
          user_pin_required: false,
        },
      },
      credentialDataSupplierInput: { firstName: 'Hello', lastName: 'World', email: 'hello.world@example.com' },
    }),
  });

  return (await credentialOffer.json()) as CreateCredentialOfferResponse;
}

async function proofOfPossessionCallbackFunction(args: Jwt, kid?: string): Promise<string> {
  const importedJwk = await importJWK(jwk, 'EdDSA');
  return await new SignJWT({ ...args.payload })
    .setProtectedHeader({ ...args.header, kid: kid! })
    .setIssuer(kid!)
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(importedJwk);
}

describe('ismapolis bug report #63, https://github.com/Sphereon-Opensource/OID4VC-demo/issues/63, should', () => {
  it('work as expected provided a correct JWT is supplied', async () => {
    debug.enable('*');
    const { uri } = await getCredentialOffer('jwt_vc_json');
    const client = await OpenID4VCIClient.fromURI({ uri: uri, clientId: 'test-clientID' });
    const metadata = await client.retrieveServerMetadata();
    console.log(JSON.stringify(metadata));

    //2. Adquire acces token from authorization server endpoint

    const accessToken = await client.acquireAccessToken({});
    console.log(`Access token: ${JSON.stringify(accessToken)}`);

    //3. Create DID needed for later proof of possession
    const { keys, didDocument } = await didts.jwk.generate({
      type: 'secp256k1', // 'P-256', 'P-384', 'X25519', 'secp256k1'
      accept: 'application/did+json',
      secureRandom: () => {
        return crypto.randomBytes(32);
      },
    });
    const edPrivateKey = await importJWK(keys[0].privateKeyJwk);

    async function signCallback(args: Jwt, kid?: string): Promise<string> {
      if (!args.payload.aud) {
        throw Error('aud required');
      } else if (!kid) {
        throw Error('kid required');
      }
      return await new SignJWT({ ...args.payload })
        .setProtectedHeader({ alg: args.header.alg, kid, typ: 'openid4vci-proof+jwt' })
        .setIssuedAt()
        .setIssuer(kid)
        .setAudience(args.payload.aud)
        .setExpirationTime('2h')
        .sign(edPrivateKey);
    }

    const callbacks: ProofOfPossessionCallbacks<never> = {
      signCallback: signCallback,
    };

    const credentialResponse = await client.acquireCredentials({
      credentialTypes: 'GuestCredential',
      proofCallbacks: callbacks,
      format: 'jwt_vc_json',
      alg: Alg.ES256K,
      kid: didDocument.verificationMethod[0].id,
      jti: v4(),
    });
    console.log(JSON.stringify(credentialResponse.credential));
  });
});
