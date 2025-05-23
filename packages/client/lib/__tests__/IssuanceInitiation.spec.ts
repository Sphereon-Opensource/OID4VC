import { OpenId4VCIVersion } from '@sphereon/oid4vci-common'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock'
import { describe, expect, it } from 'vitest'

import { CredentialOfferClient } from '../CredentialOfferClient'
import { CredentialOfferClientV1_0_11 } from '../CredentialOfferClientV1_0_11'

import { INITIATION_TEST, INITIATION_TEST_HTTPS_URI, INITIATION_TEST_URI } from './MetadataMocks'

describe('Issuance Initiation', () => {
  it('Should return Issuance Initiation Request with base URL from https URI', async () => {
    expect(await CredentialOfferClientV1_0_11.fromURI(INITIATION_TEST_HTTPS_URI)).toEqual({
      baseUrl: 'https://server.example.com',
      credential_offer: {
        credential_issuer: 'https://server.example.com',
        credentials: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        grants: {
          authorization_code: {
            issuer_state: 'eyJhbGciOiJSU0Et...FYUaBy',
          },
        },
      },
      issuerState: 'eyJhbGciOiJSU0Et...FYUaBy',
      original_credential_offer: {
        credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        issuer: 'https://server.example.com',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
      },
      scheme: 'https',
      supportedFlows: ['Authorization Code Flow'],
      userPinRequired: false,
      version: 1008,
    })
  })

  it('Should return Issuance Initiation Request with base URL from openid-initiate-issuance URI', async () => {
    expect(await CredentialOfferClient.fromURI(INITIATION_TEST_URI)).toEqual(INITIATION_TEST)
  })

  //todo: SDK-17 for removing the space
  it.skip('Should return Issuance Initiation URI from request', async () => {
    expect(CredentialOfferClient.toURI(INITIATION_TEST)).toEqual(INITIATION_TEST_URI)
  })

  it('Should return URI from Issuance Initiation Request', async () => {
    const issuanceInitiationClient = await CredentialOfferClientV1_0_11.fromURI(INITIATION_TEST_HTTPS_URI)
    expect(CredentialOfferClientV1_0_11.toURI(issuanceInitiationClient)).toEqual(INITIATION_TEST_HTTPS_URI)
  })

  it('Should throw error on invalid URI', async () => {
    const issuanceInitiationURI = INITIATION_TEST_HTTPS_URI.replace('?', '')
    await expect(async () => CredentialOfferClient.fromURI(issuanceInitiationURI)).rejects.toThrowError('Invalid Credential Offer Request')
  })

  it('Should return Credential Offer', async () => {
    const client = await CredentialOfferClient.fromURI(
      'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Flaunchpad.vii.electron.mattrlabs.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22ldp_vc%22%2C%22types%22%3A%5B%22OpenBadgeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X%22%7D%7D%7D',
    )
    expect(client.version).toEqual(OpenId4VCIVersion.VER_1_0_11)
    expect(client.baseUrl).toEqual('openid-credential-offer://')
    expect(client.scheme).toEqual('openid-credential-offer')
    expect(client.credential_offer.credential_issuer).toEqual('https://launchpad.vii.electron.mattrlabs.io')
    expect(client.preAuthorizedCode).toEqual('UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X')
  })

  it('Should take an https url as input and return a Credential Offer', async () => {
    const client = await CredentialOfferClient.fromURI(
      'https://launchpad.vii.electron.mattrlabs.io?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Flaunchpad.vii.electron.mattrlabs.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22ldp_vc%22%2C%22types%22%3A%5B%22OpenBadgeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X%22%7D%7D%7D',
    )
    expect(client.version).toEqual(OpenId4VCIVersion.VER_1_0_11)
    expect(client.baseUrl).toEqual('https://launchpad.vii.electron.mattrlabs.io')
    expect(client.scheme).toEqual('https')
    expect(client.credential_offer.credential_issuer).toEqual('https://launchpad.vii.electron.mattrlabs.io')
    expect(client.preAuthorizedCode).toEqual('UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X')
  })

  it('Should take an http url as input and return a Credential Offer', async () => {
    const client = await CredentialOfferClient.fromURI(
      'http://launchpad.vii.electron.mattrlabs.io?credential_offer=%7B%22credential_issuer%22%3A%22http%3A%2F%2Flaunchpad.vii.electron.mattrlabs.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22ldp_vc%22%2C%22types%22%3A%5B%22OpenBadgeCredential%22%5D%7D%5D%2C%22grants%22%3A%7B%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X%22%7D%7D%7D',
    )
    expect(client.version).toEqual(OpenId4VCIVersion.VER_1_0_11)
    expect(client.baseUrl).toEqual('http://launchpad.vii.electron.mattrlabs.io')
    expect(client.scheme).toEqual('http')
    expect(client.credential_offer.credential_issuer).toEqual('http://launchpad.vii.electron.mattrlabs.io')
    expect(client.preAuthorizedCode).toEqual('UPZohaodPlLBnGsqB02n2tIupCIg8nKRRUEUHWA665X')
  })

  it('Should return credenco Credential Offer', async () => {
    nock('https://mijnkvk.acc.credenco.com')
      .get('/openid4vc/credentialOffer?id=32fc4ebf-9e31-4149-9877-e3c0b602d559')
      .reply(200, {
        credential_issuer: 'https://mijnkvk.acc.credenco.com',
        credential_configuration_ids: ['BevoegdheidUittreksel_jwt_vc_json'],
        grants: {
          authorization_code: {
            issuer_state: '32fc4ebf-9e31-4149-9877-e3c0b602d559',
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code':
              'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIzMmZjNGViZi05ZTMxLTQxNDktOTg3Ny1lM2MwYjYwMmQ1NTkiLCJpc3MiOiJodHRwczovL21pam5rdmsuYWNjLmNyZWRlbmNvLmNvbSIsImF1ZCI6IlRPS0VOIn0.754aiQ87O0vHYSpRvPqAS9cLOgf-pewdeXbpLziRwsxEp9mENfaXpY62muYpzOaWcYmTOydkzhFul-NDYXJZCA',
          },
        },
      })
    const client = await CredentialOfferClient.fromURI(
      'openid-credential-offer://mijnkvk.acc.credenco.com/?credential_offer_uri=https%3A%2F%2Fmijnkvk.acc.credenco.com%2Fopenid4vc%2FcredentialOffer%3Fid%3D32fc4ebf-9e31-4149-9877-e3c0b602d559',
    )
    expect(client.version).toEqual(OpenId4VCIVersion.VER_1_0_13)
    expect(client.baseUrl).toEqual('openid-credential-offer://mijnkvk.acc.credenco.com/')
    expect(client.scheme).toEqual('openid-credential-offer')
    expect(client.credential_offer.credential_issuer).toEqual('https://mijnkvk.acc.credenco.com')
    expect(client.preAuthorizedCode).toEqual(
      'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiIzMmZjNGViZi05ZTMxLTQxNDktOTg3Ny1lM2MwYjYwMmQ1NTkiLCJpc3MiOiJodHRwczovL21pam5rdmsuYWNjLmNyZWRlbmNvLmNvbSIsImF1ZCI6IlRPS0VOIn0.754aiQ87O0vHYSpRvPqAS9cLOgf-pewdeXbpLziRwsxEp9mENfaXpY62muYpzOaWcYmTOydkzhFul-NDYXJZCA',
    )
  })
})
