import { CNonceState, CredentialIssuerMetadataOptsV1_0_15 } from '@sphereon/oid4vci-common'
import { AuthorizationServerMetadataBuilder, MemoryStates, VcIssuer } from '@sphereon/oid4vci-issuer'
import { ExpressBuilder, ExpressSupport } from '@sphereon/ssi-express-support'
import { Express } from 'express'
import requests from 'supertest'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { OID4VCIServer } from '../OID4VCIServer'

const authorizationServerMetadata = new AuthorizationServerMetadataBuilder()
  .withIssuer('test-issuer')
  .withNonceEndpoint('http://localhost:9002/nonce')
  .withCredentialEndpoint('http://localhost:9002/credential-endpoint')
  .withTokenEndpoint('http://localhost:9002/token')
  .withResponseTypesSupported(['code'])
  .build()

describe('Nonce Endpoint', () => {
  let app: Express
  let expressSupport: ExpressSupport
  let vcIssuer: VcIssuer

  beforeAll(async () => {
    vcIssuer = new VcIssuer(
      {
        credential_endpoint: 'http://localhost:9002/credential-endpoint',
        nonce_endpoint: 'http://localhost:9002/nonce',
        credential_issuer: 'test_issuer',
        credential_configurations_supported: {
          TestCredential: {
            format: 'jwt_vc_json',
            credential_definition: {
              type: ['VerifiableCredential']
            },
            cryptographic_binding_methods_supported: ['did'],
            credential_signing_alg_values_supported: ['ES256K']
          }
        }
      } as CredentialIssuerMetadataOptsV1_0_15,
      authorizationServerMetadata,
      {
        cNonceExpiresIn: 300,
        credentialOfferSessions: new MemoryStates(),
        cNonces: new MemoryStates<CNonceState>()
      }
    )

    expressSupport = ExpressBuilder.fromServerOpts({
      startListening: false,
      port: 9002,
      hostname: '0.0.0.0'
    }).build({ startListening: false })

    const vcIssuerServer = new OID4VCIServer(expressSupport, {
      issuer: vcIssuer,
      baseUrl: 'http://localhost:9002',
      endpointOpts: {
        tokenEndpointOpts: {
          tokenEndpointDisabled: true
        },
        nonceOpts: {
          enabled: true,
          baseUrl: 'http://localhost:9002'
        }
      }
    })

    expressSupport.start()
    app = vcIssuerServer.app
  })

  afterAll(async () => {
    if (expressSupport) {
      await expressSupport.stop()
    }
    await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  it('should return fresh c_nonce without authorization', async () => {
    const res = await requests(app).post('/nonce').send()

    expect(res.statusCode).toEqual(200)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      c_nonce: expect.any(String),
      c_nonce_expires_in: 300
    })
    expect(actual.c_nonce).toMatch(/^[a-f0-9-]{36}$/) // UUID format
  })

  it('should store nonce in issuer state', async () => {
    const res = await requests(app).post('/nonce').send()

    expect(res.statusCode).toEqual(200)
    const { c_nonce } = JSON.parse(res.text)

    const storedNonce = await vcIssuer.cNonces.get(c_nonce)
    expect(storedNonce).toBeDefined()
    expect(storedNonce?.cNonce).toEqual(c_nonce)
    expect(storedNonce?.createdAt).toBeTypeOf('number')
    expect(storedNonce?.expiresAt).toBeGreaterThan(Math.floor(Date.now() / 1000))
  })

  it('should return error with invalid access token', async () => {
    const res = await requests(app)
      .post('/nonce')
      .set('Authorization', 'Bearer invalid-token')
      .send()

    expect(res.statusCode).toEqual(400)
    const actual = JSON.parse(res.text)
    expect(actual).toEqual({
      error: 'invalid_token'
    })
  })

  it('should work when nonce endpoint is disabled', async () => {
    const disabledVcIssuer = new VcIssuer(
      {
        credential_endpoint: 'http://localhost:9003/credential-endpoint',
        credential_issuer: 'test_issuer',
        credential_configurations_supported: {}
      } as CredentialIssuerMetadataOptsV1_0_15,
      new AuthorizationServerMetadataBuilder()
        .withIssuer('test')
        .withResponseTypesSupported(['code'])
        .build(),
      {
        credentialOfferSessions: new MemoryStates(),
        cNonces: new MemoryStates<CNonceState>()
      }
    )

    const disabledExpressSupport = ExpressBuilder.fromServerOpts({
      startListening: false,
      port: 9003
    }).build({ startListening: false })

    new OID4VCIServer(disabledExpressSupport, {
      issuer: disabledVcIssuer,
      baseUrl: 'http://localhost:9003',
      endpointOpts: {
        tokenEndpointOpts: {
          tokenEndpointDisabled: true
        },
        nonceOpts: {
          enabled: false,
          baseUrl: 'http://localhost:9003'
        }
      }
    })

    const res = await requests(disabledExpressSupport.express).post('/nonce').send()
    expect(res.statusCode).toEqual(404)

    await disabledExpressSupport.stop()
  })
})
