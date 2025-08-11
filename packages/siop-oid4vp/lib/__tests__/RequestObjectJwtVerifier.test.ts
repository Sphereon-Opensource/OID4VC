import { parseJWT } from '@sphereon/oid4vc-common'
import * as dotenv from 'dotenv'
import { describe, expect, it } from 'vitest'

import { getJwtVerifierWithContext, getRequestObjectJwtVerifier, JwtVerifier, SIOPErrors } from '../types'

dotenv.config()

const baseJwtPayload = {
  nonce: '1234',
  scope: 'openid',
  state: '1234',
  response_type: 'id_token',
  client_id: '1234',
}

describe('requestObjectJwtVerifier', () => {
  it('should throw when an invalid schema is passed', async () => {
    expect(
      getRequestObjectJwtVerifier(
        {
          header: {},
          payload: { ...baseJwtPayload, client_id_scheme: 'wrong' as never },
        },
        { raw: '' },
      ),
    ).rejects.toThrow(SIOPErrors.INVALID_CLIENT_ID_SCHEME)
  })

  it('should succeed with a client_id_scheme did', async () => {
    const jwtVerifier = await getRequestObjectJwtVerifier(
      {
        header: { kid: 'did:example.com#1234', alg: 'ES256' },
        payload: { ...baseJwtPayload, client_id_scheme: 'did' },
      },
      { raw: '' },
    )

    const expectedJwtVerifier: JwtVerifier = { type: 'request-object', method: 'did', didUrl: 'did:example.com#1234', alg: 'ES256' }
    expect(jwtVerifier).toEqual(expectedJwtVerifier)
  })

  it('should error with a client_id_scheme did and invalid header', async () => {
    const jwtVerifier = getRequestObjectJwtVerifier(
      {
        header: {},
        payload: { ...baseJwtPayload, client_id_scheme: 'did' },
      },
      { raw: '' },
    )

    await expect(jwtVerifier).rejects.toThrow('Received an invalid JWT. Missing kid header')
  })

  it('should succeed with a client_id_scheme pre-registered', async () => {
    const jwtVerifier = await getRequestObjectJwtVerifier(
      {
        header: {},
        payload: { ...baseJwtPayload, client_id_scheme: 'pre-registered' },
      },
      { raw: '' },
    )

    const expectedJwtVerifier: JwtVerifier = { type: 'request-object', method: 'custom' }
    expect(jwtVerifier).toEqual(expectedJwtVerifier)
  })

  it('should succeed with a client_id_scheme x509_san_dns', async () => {
    const jwtVerifier = await getRequestObjectJwtVerifier(
      {
        header: { x5c: [''], alg: 'ES256' },
        payload: { ...baseJwtPayload, iss: '1234', client_id_scheme: 'x509_san_dns' },
      },
      { raw: '' },
    )

    const expectedJwtVerifier: JwtVerifier = { type: 'request-object', method: 'x5c', x5c: [''], issuer: '1234', alg: 'ES256' }
    expect(jwtVerifier).toEqual(expectedJwtVerifier)
  })

  it('should error with a client_id_scheme x509_san_dns and invalid header', async () => {
    const jwtVerifier = getRequestObjectJwtVerifier(
      {
        header: { alg: 'ES256' },
        payload: { ...baseJwtPayload, client_id_scheme: 'x509_san_dns' },
      },
      { raw: '' },
    )

    await expect(jwtVerifier).rejects.toThrow('Received an invalid JWT. Missing x5c header')
  })

  it('should error with a client_id_scheme verifier_attestation and invalid header', async () => {
    const jwtVerifier = getRequestObjectJwtVerifier(
      {
        header: {},
        payload: { ...baseJwtPayload, client_id_scheme: 'verifier_attestation' },
      },
      { raw: '' },
    )

    await expect(jwtVerifier).rejects.toThrow("Missing jwt header jwt with client_id_scheme 'verifier_attestation'")
  })

  it('should succeed with a client_id_scheme verifier_attestation', async () => {
    const attestationJwt =
      'eyJ0eXAiOiJ2ZXJpZmllci1hdHRlc3RhdGlvbitqd3QiLCAia2lkIjogImRpZDpleGFtcGxlLmNvbSMxMjM0In0.eyJzdWIiOiAiY2xpZW50X2lkIiwiaXNzIjogImlzc3VlciIsImV4cCI6IDEyMzQsImNuZiI6IHsgImp3ayI6IHt9fX0='

    const jwtVerifier = await getRequestObjectJwtVerifier(
      {
        header: { jwt: attestationJwt, typ: 'verifier-attestation+jwt', alg: 'ES256' },
        payload: { ...baseJwtPayload, client_id: 'client_id', client_id_scheme: 'verifier_attestation' },
      },
      { raw: '' },
    )

    const expectedJwtVerifier: JwtVerifier = { type: 'request-object', method: 'jwk', jwk: {}, alg: 'ES256' }
    expect(jwtVerifier).toEqual(expectedJwtVerifier)

    // const expectedAttestationVerifier: JwtVerifier = { type: 'verifier-attestation', method: 'did', didUrl: 'did:example.com#1234' }
    // const attestationJwtVerifier = await getJwtVerifierWithContext({parseJWT(attestationJwt)}, { type: 'verifier-attestation' })
    // expect(attestationJwtVerifier).toEqual(expectedAttestationVerifier)
  })
})
