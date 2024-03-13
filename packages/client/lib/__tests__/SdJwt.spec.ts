import { AccessTokenRequest, CredentialRequestV1_0_11, CredentialSupportedSdJwtVc } from '@sphereon/oid4vci-common';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock';

import { OpenID4VCIClient } from '..';
import { createAccessTokenResponse, IssuerMetadataBuilderV1_11, VcIssuerBuilder } from '../../../issuer';

export const UNIT_TEST_TIMEOUT = 30000;

const alg = 'ES256';
const jwk = { kty: 'EC', crv: 'P-256', x: 'zQOowIC1gWJtdddB5GAt4lau6Lt8Ihy771iAfam-1pc', y: 'cjD_7o3gdQ1vgiQy3_sMGs7WrwCMU9FQYimA3HxnMlw' };

const issuerMetadata = new IssuerMetadataBuilderV1_11()
  .withCredentialIssuer('https://example.com')
  .withCredentialEndpoint('https://credenital-endpoint.example.com')
  .withTokenEndpoint('https://token-endpoint.example.com')
  .addSupportedCredential({
    format: 'vc+sd-jwt',
    vct: 'SdJwtCredential',
    id: 'SdJwtCredentialId',
  })
  .build();

const vcIssuer = new VcIssuerBuilder()
  .withIssuerMetadata(issuerMetadata)
  .withInMemoryCNonceState()
  .withInMemoryCredentialOfferState()
  .withInMemoryCredentialOfferURIState()
  // TODO: see if we can construct an sd-jwt vc based on the input
  .withCredentialSignerCallback(async () => {
    return 'sd-jwt';
  })
  .withJWTVerifyCallback(() =>
    Promise.resolve({
      alg,
      jwk,
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg,
          jwk,
        },
        payload: {
          aud: issuerMetadata.credential_issuer,
          iat: +new Date(),
          nonce: 'a-c-nonce',
        },
      },
    }),
  )
  .build();

describe('sd-jwt vc', () => {
  beforeEach(() => {
    nock.cleanAll();
  });
  afterEach(() => {
    nock.cleanAll();
  });

  it(
    'succeed with a full flow',
    async () => {
      const offerUri = await vcIssuer.createCredentialOfferURI({
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': '123',
            user_pin_required: false,
          },
        },
        credentials: ['SdJwtCredentialId'],
      });

      nock(vcIssuer.issuerMetadata.credential_issuer).get('/.well-known/openid-credential-issuer').reply(200, JSON.stringify(issuerMetadata));
      nock(vcIssuer.issuerMetadata.credential_issuer).get('/.well-known/openid-configuration').reply(404);
      nock(vcIssuer.issuerMetadata.credential_issuer).get('/.well-known/oauth-authorization-server').reply(404);

      expect(offerUri.uri).toEqual(
        'openid-credential-offer://?credential_offer=%7B%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22123%22%2C%22user_pin_required%22%3Afalse%7D%7D%2C%22credentials%22%3A%5B%22SdJwtCredentialId%22%5D%2C%22credential_issuer%22%3A%22https%3A%2F%2Fexample.com%22%7D',
      );

      const client = await OpenID4VCIClient.fromURI({
        uri: offerUri.uri,
      });

      expect(client.credentialOffer?.credential_offer).toEqual({
        credential_issuer: 'https://example.com',
        credentials: ['SdJwtCredentialId'],
        grants: {
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': '123',
            user_pin_required: false,
          },
        },
      });

      const supported = client.getCredentialsSupported(true, 'vc+sd-jwt');
      expect(supported).toEqual([
        {
          vct: 'SdJwtCredential',
          format: 'vc+sd-jwt',
          id: 'SdJwtCredentialId',
        },
      ]);

      const offered = supported[0] as CredentialSupportedSdJwtVc;

      nock(issuerMetadata.token_endpoint as string)
        .post('/')
        .reply(200, async (_, body: string) => {
          const parsedBody = Object.fromEntries(body.split('&').map((x) => x.split('=')));
          return createAccessTokenResponse(parsedBody as AccessTokenRequest, {
            credentialOfferSessions: vcIssuer.credentialOfferSessions,
            accessTokenIssuer: 'https://issuer.example.com',
            cNonces: vcIssuer.cNonces,
            cNonce: 'a-c-nonce',
            accessTokenSignerCallback: async () => 'ey.val.ue',
            tokenExpiresIn: 500,
          });
        });

      await client.acquireAccessToken({});

      nock(issuerMetadata.credential_endpoint as string)
        .post('/')
        .reply(200, async (_, body) =>
          vcIssuer.issueCredential({
            credentialRequest: body as CredentialRequestV1_0_11,
            credential: {
              vct: 'Hello',
              iss: 'did:example:123',
              iat: 123,
              // Defines what can be disclosed (optional)
              __disclosureFrame: {
                name: true,
              },
            },
            newCNonce: 'new-c-nonce',
          }),
        );

      const credentials = await client.acquireCredentials({
        credentialTypes: [offered.vct],
        format: 'vc+sd-jwt',
        alg,
        jwk,
        proofCallbacks: {
          // When using sd-jwt for real, this jwt should include a jwk
          signCallback: async () => 'ey.ja.ja',
        },
      });

      expect(credentials).toEqual({
        c_nonce: 'new-c-nonce',
        c_nonce_expires_in: 300,
        credential: 'sd-jwt',
        format: 'vc+sd-jwt',
      });
    },
    UNIT_TEST_TIMEOUT,
  );
});
