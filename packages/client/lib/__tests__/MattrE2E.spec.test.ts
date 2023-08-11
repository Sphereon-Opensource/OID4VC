import { Alg, AuthzFlowType, Jwt } from '@sphereon/oid4vci-common'
import { importJWK, JWK, SignJWT } from 'jose'

import { OpenID4VCIClient } from '..'

export const UNIT_TEST_TIMEOUT = 30000

const ISSUER_URL = 'https://launchpad.vii.electron.mattrlabs.io'

const jwk: JWK = {
  'crv': 'Ed25519',
  'd': 'kTRm0aONHYwNPA-w_DtjMHUIWjE3K70qgCIhWojZ0eU',
  'x': 'NeA0d8sp86xRh3DczU4m5wPNIbl0HCSwOBcMN3sNmdk',
  'kty': 'OKP'
}

// pub  hex: 35e03477cb29f3ac518770dccd4e26e703cd21b9741c24b038170c377b0d99d9
// priv hex: 913466d1a38d1d8c0d3c0fb0fc3b633075085a31372bbd2a8022215a88d9d1e5
const did = `did:key:z6Mki5ZwZKN1dBQprfJTikUvkDxrHijiiQngkWviMF5gw2Hv`
const kid = `${did}#z6Mki5ZwZKN1dBQprfJTikUvkDxrHijiiQngkWviMF5gw2Hv`
describe('OID4VCI-Client using Mattr issuer should', () => {


  it(
    'succeed in a full flow with the client using OpenID4VCI version 11',
    async () => {
      const offer = await getCredentialOffer()
      const client = await OpenID4VCIClient.fromURI({
        uri: offer.offerUrl,
        flowType: AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
        kid,
        alg: Alg.EdDSA
      })
      expect(client.flowType).toEqual(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW)
      expect(client.credentialOffer).toBeDefined()
      expect(client.endpointMetadata).toBeDefined()
      expect(client.getCredentialEndpoint()).toEqual(`${ISSUER_URL}/oidc/v1/auth/credential`)
      expect(client.getAccessTokenEndpoint()).toEqual('https://launchpad.vii.electron.mattrlabs.io/oidc/v1/auth/token')

      const accessToken = await client.acquireAccessToken()
      console.log(accessToken)
      expect(accessToken).toMatchObject({
        expires_in: 3600,
        scope: 'OpenBadgeCredential',
        token_type: 'Bearer'
      })

      const credentialResponse = await client.acquireCredentials({
        credentialTypes: 'OpenBadgeCredential',
        format: 'ldp_vc',
        proofCallbacks: {
          signCallback: proofOfPossessionCallbackFunction
        }
      })
      expect(credentialResponse.credential).toEqual({})
    },
    UNIT_TEST_TIMEOUT
  )
})

interface CreateCredentialOfferResponse {
  id: string;
  offerUrl: string;
}

async function getCredentialOffer(): Promise<CreateCredentialOfferResponse> {
  const credentialOffer = await fetch('https://launchpad.mattrlabs.com/api/credential-offer', {
    method: 'post',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json'
    },

    //make sure to serialize your JSON body
    body: JSON.stringify({
      type: 'OpenBadgeCredential',
      userId: '622a9f65-21c0-4c0b-9a6a-f7574c2a1549',
      userAuthenticationRequired: false
    })
  })

  return (await credentialOffer.json()) as CreateCredentialOfferResponse
}

async function proofOfPossessionCallbackFunction(args: Jwt, kid?: string): Promise<string> {
  const importedJwk = await importJWK(jwk, 'EdDSA')
  return await new SignJWT({ ...args.payload })
    .setProtectedHeader({ ...args.header })
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(importedJwk)
}
