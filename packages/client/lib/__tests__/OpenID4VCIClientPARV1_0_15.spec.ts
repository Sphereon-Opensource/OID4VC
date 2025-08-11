import { PARMode, WellKnownEndpoints } from '@sphereon/oid4vci-common'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { OpenID4VCIClientV1_0_15 } from '../OpenID4VCIClientV1_0_15'

const MOCK_URL = 'https://server.example.com/'
describe('OpenID4VCIClientV1_0_15', () => {
  let client: OpenID4VCIClientV1_0_15

  const OFFER = {
    credential_issuer: MOCK_URL,
    credential_configuration_ids: ['TestCredential'],
    grants: {
      'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
        'pre-authorized_code': 'eyJhbGciOiJSU0Et...FYUaBy',
        user_pin_required: false
      }
    }
  }

  // Build the URI once, avoid hand-encoding mistakes
  const OFFER_URI = `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(OFFER))}`

  beforeEach(async () => {
    nock(MOCK_URL).get(/.*/).reply(200, {})
    nock(MOCK_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, {})
    nock(MOCK_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {})

    // PAR endpoint path is implementation-specific; keeping your existing one is fine
    nock(MOCK_URL).post('/v1/auth/par').reply(201, { request_uri: 'test_uri', expires_in: 90 })

    client = await OpenID4VCIClientV1_0_15.fromURI({
      createAuthorizationRequestURL: false,
      clientId: 'test-client',
      uri: OFFER_URI
    })
  })


  afterEach(() => {
    nock.cleanAll()
  })

  it('should successfully retrieve the authorization code using PAR', async () => {
    client.endpointMetadata.credentialIssuerMetadata!.pushed_authorization_request_endpoint = `${MOCK_URL}v1/auth/par`
    client.endpointMetadata.credentialIssuerMetadata!.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`
    const actual = await client.createAuthorizationRequestUrl({
      authorizationRequest: {
        parMode: PARMode.REQUIRE,
        scope: 'openid TestCredential',
        redirectUri: 'http://localhost:8881/cb'
      }
    })
    expect(actual).toEqual('https://server.example.com/v1/auth/authorize?client_id=test-client&request_uri=test_uri')
  })

  it('should fail when pushed_authorization_request_endpoint is not present', async () => {
    client.endpointMetadata.credentialIssuerMetadata!.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`
    await expect(() =>
      client.createAuthorizationRequestUrl({
        authorizationRequest: {
          parMode: PARMode.REQUIRE,
          scope: 'openid TestCredential',
          redirectUri: 'http://localhost:8881/cb'
        }
      })
    ).rejects.toThrow(Error('PAR mode is set to required by Authorization Server does not support PAR!'))
  })

  it('should fail when authorization_details and scope are not present', async () => {
    await expect(() =>
      client.createAuthorizationRequestUrl({
        authorizationRequest: {
          parMode: PARMode.REQUIRE,
          redirectUri: 'http://localhost:8881/cb'
        }
      })
    ).rejects.toThrow('Could not create authorization details from credential offer. Please pass in explicit details')
  })

  it('should not fail when only authorization_details is present', async () => {
    client.endpointMetadata.credentialIssuerMetadata!.pushed_authorization_request_endpoint = `${MOCK_URL}v1/auth/par`
    client.endpointMetadata.credentialIssuerMetadata!.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`
    const actual = await client.createAuthorizationRequestUrl({
      authorizationRequest: {
        parMode: PARMode.REQUIRE,
        authorizationDetails: [
          {
            type: 'openid_credential',
            format: 'ldp_vc',
            credential_definition: {
              '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
              types: ['VerifiableCredential', 'UniversityDegreeCredential']
            }
          }
        ],
        redirectUri: 'http://localhost:8881/cb'
      }
    })
    expect(actual).toEqual('https://server.example.com/v1/auth/authorize?client_id=test-client&request_uri=test_uri')
  })

  it('should not fail when only scope is present', async () => {
    client.endpointMetadata.credentialIssuerMetadata!.pushed_authorization_request_endpoint = `${MOCK_URL}v1/auth/par`
    client.endpointMetadata.credentialIssuerMetadata!.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`
    const actual = await client.createAuthorizationRequestUrl({
      authorizationRequest: {
        parMode: PARMode.REQUIRE,
        scope: 'openid TestCredential',
        redirectUri: 'http://localhost:8881/cb'
      }
    })
    expect(actual).toEqual('https://server.example.com/v1/auth/authorize?client_id=test-client&request_uri=test_uri')
  })

  it('should not fail when both authorization_details and scope are present', async () => {
    client.endpointMetadata.credentialIssuerMetadata!.pushed_authorization_request_endpoint = `${MOCK_URL}v1/auth/par`
    client.endpointMetadata.credentialIssuerMetadata!.authorization_endpoint = `${MOCK_URL}v1/auth/authorize`
    const actual = await client.createAuthorizationRequestUrl({
      authorizationRequest: {
        parMode: PARMode.REQUIRE,
        authorizationDetails: [
          {
            type: 'openid_credential',
            format: 'ldp_vc',
            credential_definition: {
              '@context': ['https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1'],
              types: ['VerifiableCredential', 'UniversityDegreeCredential']
            }
          }
        ],
        scope: 'openid TestCredential',
        redirectUri: 'http://localhost:8881/cb'
      }
    })
    expect(actual).toEqual('https://server.example.com/v1/auth/authorize?client_id=test-client&request_uri=test_uri')
  })
})
