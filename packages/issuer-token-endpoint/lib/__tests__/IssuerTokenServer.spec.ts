import { KeyObject } from 'crypto'
import * as http from 'http'

import { Alg, Jwt } from '@sphereon/openid4vci-common'
import { MemoryCNonceStateManager, MemoryCredentialOfferStateManager } from '@sphereon/openid4vci-issuer/dist/state-manager'
import { Express } from 'express'
import * as jose from 'jose'
import requests from 'supertest'

import { IssuerTokenServer } from '../IssuerTokenServer'

describe('IssuerTokenServer', () => {
  let app: Express
  let server: http.Server

  beforeAll(async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const signerCallback = async (jwt: Jwt, kid?: string): Promise<string> => {
      const privateKey = (await jose.generateKeyPair(Alg.ES256)).privateKey as KeyObject
      return new jose.SignJWT({ ...jwt.payload }).setProtectedHeader({ ...jwt.header }).sign(privateKey)
    }

    const credentialOfferState = {
      userPin: 493536,
      createdOn: +new Date(),
      credentialOffer: {
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
      },
    }
    const credentialOfferState1 = {
      ...credentialOfferState,
      credentialOffer: {
        ...credentialOfferState.credentialOffer,
        grants: {
          ...credentialOfferState.credentialOffer.grants,
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            ...credentialOfferState.credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'],
            user_pin_required: false,
          },
        },
      },
    }
    const credentialOfferState2 = { ...credentialOfferState, preAuthorizedCodeExpiresIn: 1 }
    const state = new MemoryCredentialOfferStateManager()
    await state.setState('test_state', credentialOfferState)
    await state.setState('test_state_1', credentialOfferState1)
    await state.setState('test_state_2', credentialOfferState2)

    const issuerTokenServer = new IssuerTokenServer({
      stateManager: state,
      nonceStateManager: new MemoryCNonceStateManager(),
      accessTokenSignerCallback: signerCallback,
      accessTokenIssuer: 'https://www.example.com',
      preAuthorizedCodeExpirationDuration: 2000,
    })
    app = issuerTokenServer.app
    server = issuerTokenServer.server
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
      access_token: expect.stringContaining('eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE2ODM'),
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
