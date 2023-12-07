import { Alg, Jwt } from '@sphereon/oid4vci-common';
import { CredentialMapper } from '@sphereon/ssi-types';
import { fetch } from 'cross-fetch';
import { importJWK, JWK, SignJWT } from 'jose';

import { OpenID4VCIClient } from '..';

export const UNIT_TEST_TIMEOUT = 30000;

const ISSUER_URL = 'https://launchpad.vii.electron.mattrlabs.io';

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
describe.skip('OID4VCI-Client using Mattr issuer should', () => {
  async function test(format: 'ldp_vc' | 'jwt_vc_json') {
    const offer = await getCredentialOffer(format);
    const client = await OpenID4VCIClient.fromURI({
      uri: offer.offerUrl,
      kid,
      alg: Alg.EdDSA,
    });
    expect(client.credentialOffer).toBeDefined();
    expect(client.endpointMetadata).toBeDefined();
    expect(client.getCredentialEndpoint()).toEqual(`${ISSUER_URL}/oidc/v1/auth/credential`);
    expect(client.getAccessTokenEndpoint()).toEqual('https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/token');

    const accessToken = await client.acquireAccessToken();
    // console.log(accessToken);
    expect(accessToken).toMatchObject({
      expires_in: 3600,
      scope: 'OpenBadgeCredential',
      token_type: 'Bearer',
    });

    const credentialResponse = await client.acquireCredentials({
      credentialTypes: 'OpenBadgeCredential',
      format,
      proofCallbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
    });
    expect(credentialResponse.credential).toBeDefined();
    const wrappedVC = CredentialMapper.toWrappedVerifiableCredential(credentialResponse.credential!);
    expect(format.startsWith(wrappedVC.format)).toEqual(true);
  }

  it(
    'succeed in a full flow with the client using OpenID4VCI version 11 and ldp_vc',
    async () => {
      await test('ldp_vc');
    },
    UNIT_TEST_TIMEOUT,
  );
  it(
    'succeed in a full flow with the client using OpenID4VCI version 11 and jwt_vc_json',
    async () => {
      await test('jwt_vc_json');
    },
    UNIT_TEST_TIMEOUT,
  );
});

interface CreateCredentialOfferResponse {
  id: string;
  offerUrl: string;
}

async function getCredentialOffer(format: 'ldp_vc' | 'jwt_vc_json'): Promise<CreateCredentialOfferResponse> {
  const credentialOffer = await fetch('https://launchpad.mattrlabs.com/api/credential-offer', {
    method: 'post',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },

    //make sure to serialize your JSON body
    body: JSON.stringify({
      format,
      type: 'OpenBadgeCredential',
      userId: '622a9f65-21c0-4c0b-9a6a-f7574c2a1549',
      userAuthenticationRequired: false,
    }),
  });

  return (await credentialOffer.json()) as CreateCredentialOfferResponse;
}

async function proofOfPossessionCallbackFunction(args: Jwt, kid?: string): Promise<string> {
  const importedJwk = await importJWK(jwk, 'EdDSA');
  return await new SignJWT({ ...args.payload })
    .setProtectedHeader({ ...args.header })
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(importedJwk);
}
