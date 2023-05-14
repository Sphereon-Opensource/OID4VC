import { KeyObject } from 'crypto'
import * as http from 'http'

import {
  Alg,
  CNonceState,
  CredentialIssuerMetadata,
  CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11,
  CredentialOfferSession,
  Jwt,
  URIState,
} from '@sphereon/oid4vci-common'
import { VcIssuer } from '@sphereon/oid4vci-issuer'
import { MemoryStates } from '@sphereon/oid4vci-issuer/dist/state-manager'
import { Express } from 'express'
import * as jose from 'jose'
import requests from 'supertest'
import { v4 } from 'uuid'

import { OID4VCIServer } from '../OID4VCIServer'

describe('OID4VCIServer', () => {
  let app: Express
  let server: http.Server

  beforeAll(async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const signerCallback = async (jwt: Jwt, kid?: string): Promise<string> => {
      const privateKey = (await jose.generateKeyPair(Alg.ES256)).privateKey as KeyObject
      return new jose.SignJWT({ ...jwt.payload }).setProtectedHeader({ ...jwt.header }).sign(privateKey)
    }

    const credentialOfferState1 = {
      id: v4(),
      userPin: 493536,
      createdOn: +new Date(),
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'test_issuer',
          credential_definition: {
            '@context': ['test_context'],
            types: ['VerifiableCredential'],
            credentialSubject: {},
          },
          grants: {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              user_pin_required: true,
              'pre-authorized_code': 'SplxlOBeZQQYbYS6WxSbIA',
            },
          },
        } as CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11,
      },
    }
    const credentialOfferState2 = {
      ...credentialOfferState1,
      id: v4(),
      credentialOffer: {
        ...credentialOfferState1.credentialOffer,
        credential_offer: {
          ...credentialOfferState1.credentialOffer.credential_offer,

          grants: {
            ...credentialOfferState1.credentialOffer.credential_offer.grants,
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              ...credentialOfferState1.credentialOffer.credential_offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
              user_pin_required: false,
            },
          },
        } as CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11,
      },
    }
    const credentialOfferState3 = { ...credentialOfferState1, preAuthorizedCodeExpiresIn: 1, id: v4() }
    const state = new MemoryStates<CredentialOfferSession>()
    await state.set('test_state', credentialOfferState1)
    await state.set('test_state_1', credentialOfferState2)
    await state.set('test_state_2', credentialOfferState3)

    const vcIssuer: VcIssuer = new VcIssuer(
      {
        authorization_server: 'https://authorization-server',
        credential_endpoint: 'https://credential-endpoint',
        credential_issuer: 'https://credential-issuer',
        display: [{ name: 'example issuer', locale: 'en-US' }],
        credentials_supported: [
          {
            format: 'jwt_vc_json',
            types: ['VerifiableCredential', 'UniversityDegreeCredential'],
            credentialSubject: {
              given_name: {
                display: [
                  {
                    name: 'given name',
                    locale: 'en-US',
                  },
                ],
              },
            },
            cryptographic_suites_supported: ['ES256K'],
            cryptographic_binding_methods_supported: ['did'],
            id: 'UniversityDegree_JWT',
            display: [
              {
                name: 'University Credential',
                locale: 'en-US',
                logo: {
                  url: 'https://exampleuniversity.com/public/logo.png',
                  alt_text: 'a square logo of a university',
                },
                background_color: '#12107c',
                text_color: '#FFFFFF',
              },
            ],
          },
        ],
      } as CredentialIssuerMetadata,
      {
        cNonceExpiresIn: 300,
        credentialOfferSessions: state,
        cNonces: new MemoryStates<CNonceState>(),
        uris: new MemoryStates<URIState>(),
      }
    )

    const vcIssuerServer = new OID4VCIServer({
      issuer: vcIssuer,
      tokenEndpointOpts: {
        accessTokenSignerCallback: signerCallback,
        accessTokenIssuer: 'https://www.example.com',
        preAuthorizedCodeExpirationDuration: 2000,
        tokenExpiresIn: 300000,
      },
    })
    app = vcIssuerServer.app
    server = vcIssuerServer.server
  })

  afterAll(async () => {
    await server.close(() => {
      console.log('Stopping Express server')
    })
    await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  it('should return the access token', async () => {
    const res = await requests(app)
      .post('/token')
      .send(
        'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA&user_pin=493536&state=test_state'
      )
    expect(res.statusCode).toEqual(200)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      access_token: expect.stringContaining('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE2ODQ'),
      token_type: 'bearer',
      expires_in: 300000,
      c_nonce: expect.any(String),
      c_nonce_expires_in: 300000,
      authorization_pending: false,
      interval: 300000,
    })
  })
  it('should return http code 400 with message User pin is required', async () => {
    const res = await requests(app)
      .post('/token')
      .send('grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA&state=test_state')
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_request',
      error_description: 'User pin is required',
    })
  })
  it('should return http code 400 with message pre-authorized_code is required', async () => {
    const res = await requests(app)
      .post('/token')
      .send('grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&user_pin=493536&state=test_state')
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_request',
      error_description: 'pre-authorized_code is required',
    })
  })
  it('should return http code 400 with message unsupported grant_type', async () => {
    const res = await requests(app)
      .post('/token')
      .send('grant_type=non-existent&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA&user_pin=493536&state=test_state')
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_description: 'unsupported grant_type',
    })
  })
  it('should return http code 400 with message PIN does not match', async () => {
    const res = await requests(app)
      .post('/token')
      .send(
        'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA&user_pin=493537&state=test_state'
      )
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_message: 'PIN does not match',
    })
  })
  it('should return http code 400 with message PIN must consist of maximum 8 numeric characters', async () => {
    const res = await requests(app)
      .post('/token')
      .send(
        'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA&user_pin=invalid&state=test_state'
      )
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_message: 'PIN must consist of maximum 8 numeric characters',
    })
  })
  it('should return http code 400 with message pre-authorized_code is invalid', async () => {
    const res = await requests(app)
      .post('/token')
      .send('grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=test&user_pin=493536&state=test_state')
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_message: 'pre-authorized_code is invalid',
    })
  })
  it('should return http code 400 with message User pin is not required', async () => {
    const res = await requests(app)
      .post('/token')
      .send(
        'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA&user_pin=493536&state=test_state_1'
      )
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_request',
      error_description: 'User pin is not required',
    })
  })
  it('should return http code 400 with message pre-authorized code expired', async () => {
    await new Promise((r) => setTimeout(r, 2000))
    const res = await requests(app)
      .post('/token')
      .send(
        'grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=SplxlOBeZQQYbYS6WxSbIA&user_pin=493536&state=test_state_2'
      )
    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_grant',
      error_message: 'pre-authorized_code is expired',
    })
  })
})
