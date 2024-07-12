import * as dotenv from 'dotenv'

import { getJwtVerifierWithContext, getRequestObjectJwtVerifier, JwtVerifier, SIOPErrors } from '..'
import { parseJWT } from '../helpers/jwtUtils'

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
        { type: 'request-object', raw: '' },
      ),
    ).rejects.toThrow(SIOPErrors.INVALID_CLIENT_ID_SCHEME)
  })

  it('should succeed with a client_id_scheme did', async () => {
    const jwtVerifier = await getRequestObjectJwtVerifier(
      {
        header: { kid: 'did:example.com#1234' },
        payload: { ...baseJwtPayload, client_id_scheme: 'did' },
      },
      { type: 'request-object', raw: '' },
    )

    const expectedJwtVerifier: JwtVerifier = { type: 'request-object', method: 'did', didUrl: 'did:example.com#1234' }
    expect(jwtVerifier).toEqual(expectedJwtVerifier)
  })

  it('should error with a client_id_scheme did and invalid header', async () => {
    const jwtVerifier = getRequestObjectJwtVerifier(
      {
        header: {},
        payload: { ...baseJwtPayload, client_id_scheme: 'did' },
      },
      { type: 'request-object', raw: '' },
    )

    await expect(jwtVerifier).rejects.toThrow(SIOPErrors.INVALID_REQUEST_OBJECT_DID_SCHEME_JWT)
  })

  it('should succeed with a client_id_scheme pre-registered', async () => {
    const jwtVerifier = await getRequestObjectJwtVerifier(
      {
        header: {},
        payload: { ...baseJwtPayload, client_id_scheme: 'pre-registered' },
      },
      { type: 'request-object', raw: '' },
    )

    const expectedJwtVerifier: JwtVerifier = { type: 'request-object', method: 'custom' }
    expect(jwtVerifier).toEqual(expectedJwtVerifier)
  })

  it('should succeed with a client_id_scheme x509_san_dns', async () => {
    const jwtVerifier = await getRequestObjectJwtVerifier(
      {
        header: { x5c: [''] },
        payload: { ...baseJwtPayload, iss: 'issuer', client_id_scheme: 'x509_san_dns' },
      },
      { type: 'request-object', raw: '' },
    )

    const expectedJwtVerifier: JwtVerifier = { type: 'request-object', method: 'x5c', x5c: [''], issuer: 'issuer' }
    expect(jwtVerifier).toEqual(expectedJwtVerifier)
  })

  it('should error with a client_id_scheme x509_san_dns and invalid header', async () => {
    const jwtVerifier = getRequestObjectJwtVerifier(
      {
        header: {},
        payload: { ...baseJwtPayload, client_id_scheme: 'x509_san_dns' },
      },
      { type: 'request-object', raw: '' },
    )

    await expect(jwtVerifier).rejects.toThrow(SIOPErrors.INVALID_REQUEST_OBJECT_X509_SCHEME_JWT)
  })

  it('should error with a client_id_scheme verifier_attestation and invalid header', async () => {
    const jwtVerifier = getRequestObjectJwtVerifier(
      {
        header: {},
        payload: { ...baseJwtPayload, client_id_scheme: 'verifier_attestation' },
      },
      { type: 'request-object', raw: '' },
    )

    await expect(jwtVerifier).rejects.toThrow(SIOPErrors.MISSING_ATTESTATION_JWT)
  })

  it('should succeed with a client_id_scheme verifier_attestation', async () => {
    const attestationJwt =
      'eyJ0eXAiOiJ2ZXJpZmllci1hdHRlc3RhdGlvbitqd3QiLCAia2lkIjogImRpZDpleGFtcGxlLmNvbSMxMjM0In0.eyJzdWIiOiAiY2xpZW50X2lkIiwiaXNzIjogImlzc3VlciIsImV4cCI6IDEyMzQsImNuZiI6IHsgImp3ayI6IHt9fX0='

    const jwtVerifier = await getRequestObjectJwtVerifier(
      {
        header: { jwt: attestationJwt, typ: 'verifier-attestation+jwt' },
        payload: { ...baseJwtPayload, client_id: 'client_id', client_id_scheme: 'verifier_attestation' },
      },
      { type: 'request-object', raw: '' },
    )

    const expectedJwtVerifier: JwtVerifier = { type: 'request-object', method: 'jwk', jwk: {} }
    expect(jwtVerifier).toEqual(expectedJwtVerifier)

    const expectedAttestationVerifier: JwtVerifier = { type: 'verifier-attestation', method: 'did', didUrl: 'did:example.com#1234' }
    const attestationJwtVerifier = await getJwtVerifierWithContext(parseJWT(attestationJwt), { type: 'verifier-attestation' })
    expect(attestationJwtVerifier).toEqual(expectedAttestationVerifier)
  })
})
