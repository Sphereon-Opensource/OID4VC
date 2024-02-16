import { Alg, Jwt } from '@sphereon/oid4vci-common';
import { toJwk } from '@sphereon/ssi-sdk-ext.key-utils';
import { CredentialMapper } from '@sphereon/ssi-types';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-ignore
import { from } from '@trust/keyto';
import { fetch } from 'cross-fetch';
import debug from 'debug';
import { base64url, importJWK, JWK, SignJWT } from 'jose';
import * as u8a from 'uint8arrays';

import { OpenID4VCIClient } from '..';

export const UNIT_TEST_TIMEOUT = 30000;

const ISSUER_URL = 'https://conformance-test.ebsi.eu/conformance/v3/issuer-mock';
const AUTH_URL = 'https://conformance-test.ebsi.eu/conformance/v3/auth-mock';

const jwk: JWK = {
  alg: 'ES256',
  use: 'sig',
  kty: 'EC',
  crv: 'P-256',
  x: 'hUWYK06qFvdudydiqnEhVJhZ-73jcLtuzH8kIyNOSHE',
  y: 'UZf7oUkJdo65SQekMD5ssiRclEimG2SmlsjXf3QwQJo',
  d: 'zDeeo3K0Pk8dofeKcajvJYxMZ1vijx_cVDJQl1IpbAM',
};

console.log(`JWK (private/orig): ${JSON.stringify(jwk, null, 2)}`);

const privateKey = from(jwk, 'jwk').toString('blk', 'private');
const publicKey = from(jwk, 'jwk').toString('blk', 'public');
console.log(`Private key: ${privateKey}`);
console.log(`Public key: ${publicKey}`);
console.log(`Private key (b64): ${base64url.encode(u8a.fromString(privateKey, 'base16'))}`);
console.log(`JWK (private 2) ${JSON.stringify(toJwk(privateKey, 'Secp256r1', { isPrivateKey: true }))}`);
console.log(`JWK (public  2) ${JSON.stringify(toJwk(publicKey, 'Secp256r1', { isPrivateKey: false }))}`);

// const DID_METHOD = 'did:key'
const DID =
  'did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbrm54tL4pRrDDhR1QJ5RHPMXUq5MzYpZL2k35vya5eMiNxschNy9AJ74CC3MmcYiZJGZfyhWQ6qDgTVcDSHdquwPYvLDut383JbrgYdZYYSC2merTMgmQtUi3huYhaky1qE';
const DID_URL_ENCODED =
  'did%3Akey%3Az2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbrm54tL4pRrDDhR1QJ5RHPMXUq5MzYpZL2k35vya5eMiNxschNy9AJ74CC3MmcYiZJGZfyhWQ6qDgTVcDSHdquwPYvLDut383JbrgYdZYYSC2merTMgmQtUi3huYhaky1qE';
// const PRIVATE_KEY_HEX = '7dd923e40f4615ac496119f7e793cc2899e99b64b88ca8603db986700089532b'

// const PUBLIC_KEY_HEX =
//   '04a23cb4c83901acc2eb0f852599610de0caeac260bf8ed05e7f902eaac0f9c8d74dd4841b94d13424d32af8ec0e9976db9abfa7e3a59e10d565c5d4d901b4be63'

// pub  hex: 35e03477cb29f3ac518770dccd4e26e703cd21b9741c24b038170c377b0d99d9
// priv hex: 913466d1a38d1d8c0d3c0fb0fc3b633075085a31372bbd2a8022215a88d9d1e5
// const did = `did:key:z6Mki5ZwZKN1dBQprfJTikUvkDxrHijiiQngkWviMF5gw2Hv`;
const kid = `${DID}#z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbrm54tL4pRrDDhR1QJ5RHPMXUq5MzYpZL2k35vya5eMiNxschNy9AJ74CC3MmcYiZJGZfyhWQ6qDgTVcDSHdquwPYvLDut383JbrgYdZYYSC2merTMgmQtUi3huYhaky1qE`;

// const jw = jose.importKey()

// EBSI returning a 500 in credential endpoint all of a sudden
describe.skip('OID4VCI-Client using Sphereon issuer should', () => {
  async function test(credentialType: 'CTWalletCrossPreAuthorisedInTime' | 'CTWalletCrossPreAuthorisedDeferred' | 'CTWalletCrossAuthorisedInTime') {
    debug.enable('*');
    const offer = await getCredentialOffer(credentialType);
    const client = await OpenID4VCIClient.fromURI({
      uri: offer,
      kid,
      alg: Alg.ES256,
      clientId: DID_URL_ENCODED,
    });
    expect(client.credentialOffer).toBeDefined();
    expect(client.endpointMetadata).toBeDefined();
    expect(client.getCredentialEndpoint()).toEqual(`${ISSUER_URL}/credential`);
    expect(client.getAccessTokenEndpoint()).toEqual(`${AUTH_URL}/token`);

    if (credentialType !== 'CTWalletCrossPreAuthorisedInTime') {
      const url = await client.createAuthorizationRequestUrl({
        authorizationRequest: {
          redirectUri: 'openid4vc%3A',
        },
      });
      const result = await fetch(url);
      console.log(result.text());
    }

    const accessToken = await client.acquireAccessToken({ pin: '0891' });
    // console.log(accessToken);
    expect(accessToken).toMatchObject({
      expires_in: 86400,
      // scope: 'GuestCredential',
      token_type: 'Bearer',
    });

    const format = 'jwt_vc';
    const credentialResponse = await client.acquireCredentials({
      credentialTypes: client.getCredentialOfferTypes()[0],
      format,
      proofCallbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
      kid,
      deferredCredentialAwait: true,
      deferredCredentialIntervalInMS: 5000,
    });
    console.log(JSON.stringify(credentialResponse, null, 2));
    expect(credentialResponse.credential).toBeDefined();
    const wrappedVC = CredentialMapper.toWrappedVerifiableCredential(credentialResponse.credential!);
    expect(format.startsWith(wrappedVC.format)).toEqual(true);
  }

  // Current conformance tests is not stable as changes are being applied it seems

  it(
    'succeed in a full flow with the client using OpenID4VCI version 11 and jwt_vc_json',
    async () => {
      await test('CTWalletCrossPreAuthorisedInTime');
      await test('CTWalletCrossPreAuthorisedDeferred');
      // await test('CTWalletCrossAuthorisedInTime');
    },
    UNIT_TEST_TIMEOUT,
  );
});

async function getCredentialOffer(
  credentialType: 'CTWalletCrossPreAuthorisedInTime' | 'CTWalletCrossAuthorisedInTime' | 'CTWalletCrossPreAuthorisedDeferred',
): Promise<string> {
  const credentialOffer = await fetch(
    `https://conformance-test.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?credential_type=${credentialType}&client_id=${DID_URL_ENCODED}&credential_offer_endpoint=openid-credential-offer%3A%2F%2F`,
    {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
    },
  );

  return await credentialOffer.text();
}

async function proofOfPossessionCallbackFunction(args: Jwt, kid?: string): Promise<string> {
  const importedJwk = await importJWK(jwk);
  return await new SignJWT({ ...args.payload })
    .setProtectedHeader({ ...args.header, kid: kid! })
    .setIssuer(DID)
    .setIssuedAt()
    .setExpirationTime('2m')
    .sign(importedJwk);
}
