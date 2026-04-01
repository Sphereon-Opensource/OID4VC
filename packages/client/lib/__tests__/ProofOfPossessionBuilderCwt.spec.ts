import { describe, expect, it, vi } from 'vitest'
import {
  OpenId4VCIVersion,
  ProofOfPossessionCallbacks,
  CWTSignerCallback,
} from '@sphereon/oid4vci-common'
import { ProofOfPossessionBuilder } from '..'

describe('ProofOfPossessionBuilder - CWT Support', () => {
  const ISSUER_URL = 'https://issuer.example.com'

  const mockCwtSignCallback: CWTSignerCallback = vi.fn().mockResolvedValue('mock-cwt-base64url')
  const mockJwtSignCallback = vi.fn().mockResolvedValue('mock.jwt.value')

  const callbacks: ProofOfPossessionCallbacks = {
    signCallback: mockJwtSignCallback,
    cwtSignCallback: mockCwtSignCallback,
  }

  it('should build a CWT proof when proofType is cwt', async () => {
    const proof = await ProofOfPossessionBuilder.fromAccessTokenResponse({
      accessTokenResponse: { access_token: 'token', token_type: 'Bearer', c_nonce: 'test-nonce' },
      callbacks,
      version: OpenId4VCIVersion.VER_1_0,
    })
      .withIssuer(ISSUER_URL)
      .withAlg('ES256')
      .withProofType('cwt')
      .withClientId('wallet-client')
      .build()

    expect(proof.proof_type).toBe('cwt')
    expect('cwt' in proof && proof.cwt).toBe('mock-cwt-base64url')
    expect(mockCwtSignCallback).toHaveBeenCalledWith(
      expect.objectContaining({
        aud: ISSUER_URL,
        nonce: 'test-nonce',
        alg: 'ES256',
      }),
    )
  })

  it('should default to JWT proof when proofType is not set', async () => {
    const jwtCallback = vi.fn().mockResolvedValue('eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature')
    const proof = await ProofOfPossessionBuilder.fromAccessTokenResponse({
      accessTokenResponse: { access_token: 'token', token_type: 'Bearer', c_nonce: 'nonce' },
      callbacks: { signCallback: jwtCallback },
      version: OpenId4VCIVersion.VER_1_0,
    })
      .withIssuer(ISSUER_URL)
      .withAlg('ES256')
      .withKid('did:example:123#key-1')
      .withClientId('wallet')
      .build()

    expect(proof.proof_type).toBe('jwt')
    expect('jwt' in proof).toBe(true)
  })

  it('should pass coseKey to CWT callback', async () => {
    const cwtCallback: CWTSignerCallback = vi.fn().mockResolvedValue('cwt-with-cose-key')
    const coseKey = { kty: 2, crv: 1, x: 'test-x', y: 'test-y' }

    await ProofOfPossessionBuilder.fromAccessTokenResponse({
      accessTokenResponse: { access_token: 'token', token_type: 'Bearer' },
      callbacks: { signCallback: vi.fn(), cwtSignCallback: cwtCallback },
      version: OpenId4VCIVersion.VER_1_0,
    })
      .withIssuer(ISSUER_URL)
      .withProofType('cwt')
      .withCoseKey(coseKey)
      .withAlg('ES256')
      .build()

    expect(cwtCallback).toHaveBeenCalledWith(
      expect.objectContaining({
        coseKey,
      }),
    )
  })

  it('should fall back to JWT if proofType is cwt but no cwtSignCallback provided', async () => {
    const jwtCallback = vi.fn().mockResolvedValue('eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature')
    const proof = await ProofOfPossessionBuilder.fromAccessTokenResponse({
      accessTokenResponse: { access_token: 'token', token_type: 'Bearer', c_nonce: 'nonce' },
      callbacks: { signCallback: jwtCallback },
      version: OpenId4VCIVersion.VER_1_0,
    })
      .withIssuer(ISSUER_URL)
      .withAlg('ES256')
      .withKid('did:example:123#key-1')
      .withClientId('wallet')
      .withProofType('cwt')
      .build()

    // Falls back to JWT because cwtSignCallback is missing
    expect(proof.proof_type).toBe('jwt')
  })
})
