import {
  AuthorizationServerMetadata,
  getIssuerFromCredentialOfferPayload,
  PRE_AUTH_GRANT_LITERAL,
  WellKnownEndpoints,
} from '@sphereon/oid4vci-common'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock'
import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { CredentialOfferClientV1_0_15 } from '../CredentialOfferClientV1_0_15'
import { MetadataClient } from '../MetadataClient'
import { determineWellknownLocations, retrieveWellknown } from '../functions/OpenIDUtils'

import {
  DANUBE_ISSUER_URL,
  DANUBE_OIDC_METADATA,
  IDENTIPROOF_AS_METADATA,
  IDENTIPROOF_AS_URL,
  IDENTIPROOF_ISSUER_URL,
  IDENTIPROOF_OID4VCI_METADATA,
  SPRUCE_ISSUER_URL,
  SPRUCE_OID4VCI_METADATA,
  WALT_ISSUER_URL,
  WALT_OID4VCI_METADATA,
} from './MetadataMocks'
import { getMockData } from './data/VciDataFixtures'
//todo: skipping this. it was written for pre v13 version and we have to do some modifications to make it work
describe('MetadataClient with IdentiProof Issuer should', () => {
  beforeAll(() => {
    nock.cleanAll()
  })

  afterEach(() => {
    nock.cleanAll()
  })

  it('succeed with OID4VCI and separate AS metadata', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA))

    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA))
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404)

    const metadata = await MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL)
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential')
    expect(metadata.token_endpoint).toEqual('https://auth.research.identiproof.io/oauth2/token')
    expect(metadata.credentialIssuerMetadata).toMatchObject(IDENTIPROOF_OID4VCI_METADATA)
  })

  it('succeed with OID4VCI and separate AS metadata from Initiation', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA))
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA))
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404)

    const INITIATE_URI =
      'openid-initiate-issuance://?credential_offer=eyJjcmVkZW50aWFsX2lzc3VlciI6Imh0dHBzOi8vaXNzdWVyLnJlc2VhcmNoLmlkZW50aXByb29mLmlvIiwiY3JlZGVudGlhbF9jb25maWd1cmF0aW9uX2lkcyI6WyJPcGVuQmFkZ2VDcmVkZW50aWFsIl0sImdyYW50cyI6eyJ1cm46aWV0ZjpwYXJhbXM6b2F1dGg6Z3JhbnQtdHlwZTpwcmUtYXV0aG9yaXplZF9jb2RlIjp7InByZS1hdXRob3JpemVkX2NvZGUiOiJleUowZVhBaU9pSktWMVFpTENKaGJHY2lPaUpJVXpJMU5pSjkuZXlKemRXSWlPaUpoT1RVeVpqVXhOaTFqWVdWbUxUUTRZak10T0RJeFl5MDBPVFJrWXpneU5qbGpaakFpTENKd2NtVXRZWFYwYUc5eWFYcGxaQ0k2ZEhKMVpYMC5ZRTVEbGFsY0xDMkNoR0VnNDdDUURhTjFnVHhiYVFxU2NsSVZxc1NBVUhFIiwidXNlcl9waW5fcmVxdWlyZWQiOmZhbHNlfX19'

    const initiation = await CredentialOfferClientV1_0_15.fromURI(INITIATE_URI)
    const metadata = await MetadataClient.retrieveAllMetadata(getIssuerFromCredentialOfferPayload(initiation.credential_offer) as string)
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential')
    expect(metadata.token_endpoint).toEqual('https://auth.research.identiproof.io/oauth2/token')
    expect(metadata.credentialIssuerMetadata).toEqual(IDENTIPROOF_OID4VCI_METADATA)
  })

  it('Fail without OID4VCI and only AS metadata (no credential endpoint)', async () => {
    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OPENID4VCI_ISSUER)
      .reply(404, JSON.stringify({ error: 'does not exist' }))

    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OPENID_CONFIGURATION)
      .reply(404, JSON.stringify({ error: 'does not exist' }))

    nock(IDENTIPROOF_ISSUER_URL)
      .get(WellKnownEndpoints.OAUTH_AS)
      .reply(404, JSON.stringify({ error: 'does not exist' }))

    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Issuer https://issuer.research.identiproof.io does not expose /.well-known/openid-credential-issuer',
    )
  })

  it('Fail with OID4VCI and no AS metadata', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA))
    nock(IDENTIPROOF_AS_URL)
      .get(WellKnownEndpoints.OPENID_CONFIGURATION)
      .reply(404, JSON.stringify({ error: 'does not exist' }))

    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, JSON.stringify({}))
    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL)).rejects.toThrowError(
      'Issuer https://issuer.research.identiproof.io provided a separate authorization server https://auth.research.identiproof.io, but that server did not provide metadata',
    )
  })

  it('Fail if there is no token endpoint with errors enabled', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA))
    const meta = JSON.parse(JSON.stringify(IDENTIPROOF_AS_METADATA))
    delete meta.token_endpoint
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(meta))
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404)

    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Authorization Server https://auth.research.identiproof.io did not provide a token_endpoint',
    )
  })

  it('Fail if there is no credential endpoint with errors enabled', async () => {
    const meta = JSON.parse(JSON.stringify(IDENTIPROOF_OID4VCI_METADATA))
    delete meta.credential_endpoint
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(meta))
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA))
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404)

    await expect(() => MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Could not deduce the credential endpoint for https://issuer.research.identiproof.io',
    )
  })

  it('Succeed with default value if there is no credential endpoint with errors disabled', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(IDENTIPROOF_OID4VCI_METADATA))
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OAUTH_AS).reply(200, JSON.stringify(IDENTIPROOF_AS_METADATA))
    nock(IDENTIPROOF_AS_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404)

    const metadata = await MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL)
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential')
  })

  it('Succeed with no well-known endpoints and errors disabled', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, {
      credential_issuer: IDENTIPROOF_ISSUER_URL,
      credential_endpoint: 'https://issuer.research.identiproof.io/credential',
      credential_configurations_supported: {},
    })
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, {})
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {})

    const metadata = await MetadataClient.retrieveAllMetadata(IDENTIPROOF_ISSUER_URL)
    expect(metadata.credential_endpoint).toEqual('https://issuer.research.identiproof.io/credential')
  })

  it('Fail when specific well-known is not found with errors enabled', async () => {
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(404, {})
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404, {})
    nock(IDENTIPROOF_ISSUER_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404, {})

    const metadata = retrieveWellknown(IDENTIPROOF_ISSUER_URL, WellKnownEndpoints.OPENID4VCI_ISSUER, { errorOnNotFound: true })
    await expect(metadata).rejects.toThrowError('{"error": "not found"}')
  })
})

describe('Metadataclient with Spruce Issuer should', () => {
  it('succeed with OID4VCI and separate AS metadata', async () => {
    nock(SPRUCE_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(SPRUCE_OID4VCI_METADATA))
    nock(SPRUCE_ISSUER_URL).get(WellKnownEndpoints.OPENID_CONFIGURATION).reply(404)
    nock(SPRUCE_ISSUER_URL).get(WellKnownEndpoints.OAUTH_AS).reply(404)

    const metadata = await MetadataClient.retrieveAllMetadata(SPRUCE_ISSUER_URL)
    expect(metadata.credential_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/credential')
    expect(metadata.token_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/token')
    expect(metadata.credentialIssuerMetadata).toEqual(SPRUCE_OID4VCI_METADATA)
  })

  it('Fail without OID4VCI', async () => {
    nock(SPRUCE_ISSUER_URL)
      .get(/.*/)
      .times(3)
      .reply(404, JSON.stringify({ error: 'does not exist' }))

    await expect(() => MetadataClient.retrieveAllMetadata(SPRUCE_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Issuer https://ngi-oidc4vci-test.spruceid.xyz does not expose /.well-known/openid-credential-issuer',
    )
  })
})

describe('Metadataclient with Danubetech should', () => {
  it('Fail without OID4VCI', async () => {
    nock(SPRUCE_ISSUER_URL)
      .get(/.*/)
      .times(3)
      .reply(404, JSON.stringify({ error: 'does not exist' }))

    await expect(() => MetadataClient.retrieveAllMetadata(SPRUCE_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Issuer https://ngi-oidc4vci-test.spruceid.xyz does not expose /.well-known/openid-credential-issuer',
    )
  })
})

describe('Metadataclient with Walt-id should', () => {
  it('succeed without OID4VCI and with OIDC metadata', async () => {
    // Walt-id issuer has a path component (/issuer-api/oidc) and only exposes the legacy (draft) well-known locations
    nock('https://jff.walt.id')
      .get(/^\/\.well-known\/.*/)
      .times(3)
      .reply(404, JSON.stringify({ error: 'does not exist' }))
    nock(WALT_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(WALT_OID4VCI_METADATA))

    nock(WALT_ISSUER_URL)
      .get(/.well-known\/.*/)
      .times(2)
      .reply(404, JSON.stringify({ error: 'does not exist' }))

    const metadata = await MetadataClient.retrieveAllMetadata(WALT_ISSUER_URL)
    expect(metadata.credential_endpoint).toEqual('https://jff.walt.id/issuer-api/oidc/credential')
    expect(metadata.token_endpoint).toEqual('https://jff.walt.id/issuer-api/oidc/token')
    expect(metadata.credentialIssuerMetadata).toEqual(WALT_OID4VCI_METADATA)
  })

  it('Fail without OID4VCI', async () => {
    nock(WALT_ISSUER_URL)
      .get(/.*/)
      .times(4)
      .reply(404, JSON.stringify({ error: 'does not exist' }))

    await expect(() => MetadataClient.retrieveAllMetadata(WALT_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      'Issuer https://jff.walt.id/issuer-api/oidc does not expose /.well-known/openid-credential-issuer',
    )
  })
})

// Spruce gives back 404's these days, so test is disabled
describe.skip('Metadataclient with SpruceId should', () => {
  beforeAll(() => {
    nock.cleanAll()
  })

  afterEach(() => {
    nock.cleanAll()
  })
  it('succeed without OID4VCI and with OIDC metadata', async () => {
    /*nock(WALT_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(WALT_OID4VCI_METADATA));

    nock(WALT_ISSUER_URL)
      .get(/.well-known\/.*!/)
      .times(2)
      .reply(404, JSON.stringify({ error: 'does not exist' }));
*/
    const metadata = await MetadataClient.retrieveAllMetadata('https://ngi-oidc4vci-test.spruceid.xyz')
    expect(metadata.credential_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/credential')
    expect(metadata.token_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/token')
    expect(metadata.credentialIssuerMetadata).toEqual({
      issuer: 'https://ngi-oidc4vci-test.spruceid.xyz',
      credential_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/credential',
      token_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/token',
      jwks_uri: 'https://ngi-oidc4vci-test.spruceid.xyz/jwks',
      grant_types_supported: [PRE_AUTH_GRANT_LITERAL],
      credentials_supported: {
        OpenBadgeCredential: {
          formats: {
            jwt_vc: {
              types: ['VerifiableCredential', 'OpenBadgeCredential'],
              cryptographic_binding_methods_supported: ['did'],
              cryptographic_suites_supported: ['ES256', 'ES256K'],
            },
            ldp_vc: {
              types: ['VerifiableCredential', 'OpenBadgeCredential'],
              cryptographic_binding_methods_supported: ['did'],
              cryptographic_suites_supported: ['Ed25519Signature2018'],
            },
          },
        },
      },
    })
  })

  it('succeed without OID4VCI and with OIDC metadata of credenco', async () => {
    /*nock(WALT_ISSUER_URL).get(WellKnownEndpoints.OPENID4VCI_ISSUER).reply(200, JSON.stringify(WALT_OID4VCI_METADATA));

    nock(WALT_ISSUER_URL)
      .get(/.well-known\/.*!/)
      .times(2)
      .reply(404, JSON.stringify({ error: 'does not exist' }));
*/
    const metadata = await MetadataClient.retrieveAllMetadata('https://mijnkvk.acc.credenco.com/')
    expect(metadata.credential_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/credential')
    expect(metadata.token_endpoint).toEqual('https://ngi-oidc4vci-test.spruceid.xyz/token')
    expect(metadata.credentialIssuerMetadata).toEqual({
      issuer: 'https://ngi-oidc4vci-test.spruceid.xyz',
      credential_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/credential',
      token_endpoint: 'https://ngi-oidc4vci-test.spruceid.xyz/token',
      jwks_uri: 'https://ngi-oidc4vci-test.spruceid.xyz/jwks',
      grant_types_supported: [PRE_AUTH_GRANT_LITERAL],
      credentials_supported: {
        OpenBadgeCredential: {
          formats: {
            jwt_vc: {
              types: ['VerifiableCredential', 'OpenBadgeCredential'],
              cryptographic_binding_methods_supported: ['did'],
              cryptographic_suites_supported: ['ES256', 'ES256K'],
            },
            ldp_vc: {
              types: ['VerifiableCredential', 'OpenBadgeCredential'],
              cryptographic_binding_methods_supported: ['did'],
              cryptographic_suites_supported: ['Ed25519Signature2018'],
            },
          },
        },
      },
    })
  })
})

describe('determineWellknownLocations should', () => {
  const TENANT_HOST = 'https://issuer.example.com'
  const TENANT_PATH = '/tenant/1234'
  const TENANT_ISSUER_URL = `${TENANT_HOST}${TENANT_PATH}`

  it('return the OID4VCI 1.0 final location first and the legacy location as fallback for issuers with a path', () => {
    expect(determineWellknownLocations(TENANT_ISSUER_URL, WellKnownEndpoints.OPENID4VCI_ISSUER)).toEqual([
      `${TENANT_HOST}/.well-known/openid-credential-issuer${TENANT_PATH}`,
      `${TENANT_ISSUER_URL}/.well-known/openid-credential-issuer`,
    ])
  })

  it('return the RFC 8414 location first and the legacy location as fallback for oauth-authorization-server with a path', () => {
    expect(determineWellknownLocations(TENANT_ISSUER_URL, WellKnownEndpoints.OAUTH_AS)).toEqual([
      `${TENANT_HOST}/.well-known/oauth-authorization-server${TENANT_PATH}`,
      `${TENANT_ISSUER_URL}/.well-known/oauth-authorization-server`,
    ])
  })

  it('return the OIDC Discovery (appended) location first and the RFC 8414 location as fallback for openid-configuration with a path', () => {
    expect(determineWellknownLocations(TENANT_ISSUER_URL, WellKnownEndpoints.OPENID_CONFIGURATION)).toEqual([
      `${TENANT_ISSUER_URL}/.well-known/openid-configuration`,
      `${TENANT_HOST}/.well-known/openid-configuration${TENANT_PATH}`,
    ])
  })

  it('return a single location when the issuer has no path component', () => {
    expect(determineWellknownLocations(TENANT_HOST, WellKnownEndpoints.OPENID4VCI_ISSUER)).toEqual([
      `${TENANT_HOST}/.well-known/openid-credential-issuer`,
    ])
  })

  it('handle trailing slashes on the issuer identifier', () => {
    expect(determineWellknownLocations(`${TENANT_ISSUER_URL}/`, WellKnownEndpoints.OPENID4VCI_ISSUER)).toEqual([
      `${TENANT_HOST}/.well-known/openid-credential-issuer${TENANT_PATH}`,
      `${TENANT_ISSUER_URL}/.well-known/openid-credential-issuer`,
    ])
  })
})

describe('MetadataClient with path-based (multi-tenant) credential issuer should', () => {
  const TENANT_HOST = 'https://issuer.example.com'
  const TENANT_PATH = '/tenant/1234'
  const TENANT_ISSUER_URL = `${TENANT_HOST}${TENANT_PATH}`
  const TENANT_OID4VCI_METADATA = {
    credential_issuer: TENANT_ISSUER_URL,
    credential_endpoint: `${TENANT_ISSUER_URL}/credential`,
    token_endpoint: `${TENANT_ISSUER_URL}/token`,
    credential_configurations_supported: {
      'org.iso.18013.5.1.mDL': {
        format: 'mso_mdoc',
        doctype: 'org.iso.18013.5.1.mDL',
      },
    },
  }

  const nockAuthorizationServer404s = () => {
    nock(TENANT_HOST).get(`${TENANT_PATH}${WellKnownEndpoints.OPENID_CONFIGURATION}`).reply(404, {})
    nock(TENANT_HOST).get(`${WellKnownEndpoints.OPENID_CONFIGURATION}${TENANT_PATH}`).reply(404, {})
    nock(TENANT_HOST).get(`${WellKnownEndpoints.OAUTH_AS}${TENANT_PATH}`).reply(404, {})
    nock(TENANT_HOST).get(`${TENANT_PATH}${WellKnownEndpoints.OAUTH_AS}`).reply(404, {})
  }

  beforeEach(() => {
    nock.cleanAll()
    nock.disableNetConnect()
  })

  afterEach(() => {
    nock.cleanAll()
    nock.enableNetConnect()
  })

  it('retrieve metadata from the OID4VCI 1.0 final well-known location (inserted between host and path)', async () => {
    nock(TENANT_HOST).get(`${WellKnownEndpoints.OPENID4VCI_ISSUER}${TENANT_PATH}`).reply(200, JSON.stringify(TENANT_OID4VCI_METADATA))
    nockAuthorizationServer404s()

    const metadata = await MetadataClient.retrieveAllMetadata(TENANT_ISSUER_URL)
    expect(metadata.credential_endpoint).toEqual(`${TENANT_ISSUER_URL}/credential`)
    expect(metadata.token_endpoint).toEqual(`${TENANT_ISSUER_URL}/token`)
    expect(metadata.credentialIssuerMetadata).toMatchObject(TENANT_OID4VCI_METADATA)
  })

  it('fall back to the legacy (draft) well-known location when the 1.0 final location is not available', async () => {
    nock(TENANT_HOST).get(`${WellKnownEndpoints.OPENID4VCI_ISSUER}${TENANT_PATH}`).reply(404, {})
    nock(TENANT_HOST).get(`${TENANT_PATH}${WellKnownEndpoints.OPENID4VCI_ISSUER}`).reply(200, JSON.stringify(TENANT_OID4VCI_METADATA))
    nockAuthorizationServer404s()

    const metadata = await MetadataClient.retrieveAllMetadata(TENANT_ISSUER_URL)
    expect(metadata.credential_endpoint).toEqual(`${TENANT_ISSUER_URL}/credential`)
    expect(metadata.credentialIssuerMetadata).toMatchObject(TENANT_OID4VCI_METADATA)
  })

  it('fail when neither the 1.0 final nor the legacy well-known location is available', async () => {
    nock(TENANT_HOST).get(`${WellKnownEndpoints.OPENID4VCI_ISSUER}${TENANT_PATH}`).reply(404, {})
    nock(TENANT_HOST).get(`${TENANT_PATH}${WellKnownEndpoints.OPENID4VCI_ISSUER}`).reply(404, {})

    await expect(() => MetadataClient.retrieveAllMetadata(TENANT_ISSUER_URL, { errorOnNotFound: true })).rejects.toThrowError(
      `Issuer ${TENANT_ISSUER_URL} does not expose /.well-known/openid-credential-issuer`,
    )
  })
})

describe('Metadataclient with Credenco should', () => {
  beforeEach(() => {
    const mockData = getMockData('credenco')
    if (!mockData?.metadata?.openid4vci_metadata) {
      throw new Error('Credenco mock data not found or invalid structure')
    }
    nock('https://mijnkvk.acc.credenco.com').get('/.well-known/openid-credential-issuer').reply(200, mockData.metadata.openid4vci_metadata)
    nock('https://mijnkvk.acc.credenco.com').get('/.well-known/openid-configuration').reply(404)
    const authMetadata: AuthorizationServerMetadata = {
      authorization_endpoint: 'https://mijnkvk.acc.credenco.com',
      'pre-authorized_grant_anonymous_access_supported': true,
      issuer: 'https://issuer.research.identiproof.io',
      token_endpoint: 'https://mijnkvk.acc.credenco.com/token',
      response_types_supported: ['token'],
    }
    nock('https://mijnkvk.acc.credenco.com').get('/.well-known/oauth-authorization-server').reply(200, JSON.stringify(authMetadata))
  })

  it('succeed without OID4VCI and with OIDC metadata', async () => {
    const metadata = await MetadataClient.retrieveAllMetadata('https://mijnkvk.acc.credenco.com/')
    expect(metadata.credential_endpoint).toEqual('https://mijnkvk.acc.credenco.com/credential')
    expect(metadata.token_endpoint).toEqual('https://mijnkvk.acc.credenco.com/token')
    expect(metadata.credentialIssuerMetadata?.credential_configurations_supported).toEqual(
      getMockData('credenco')?.metadata.openid4vci_metadata.credential_configurations_supported,
    )
  })
})
