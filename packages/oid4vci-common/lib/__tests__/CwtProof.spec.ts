import { describe, expect, it, vi } from 'vitest'
import { createCwtProofOfPossession, ProofOfPossessionCallbacks, CWTSignerCallback } from '../index'

describe('CWT Proof of Possession', () => {
  const mockCwtSignCallback: CWTSignerCallback = vi.fn().mockResolvedValue('base64url-encoded-cwt-value')

  it('should create a CWT proof of possession', async () => {
    const callbacks: ProofOfPossessionCallbacks = {
      signCallback: vi.fn(),
      cwtSignCallback: mockCwtSignCallback,
    }
    const proof = await createCwtProofOfPossession(callbacks, {
      iss: 'https://wallet.example.com',
      aud: 'https://issuer.example.com',
      nonce: 'test-nonce',
      alg: 'ES256',
    })
    expect(proof.proof_type).toBe('cwt')
    expect(proof.cwt).toBe('base64url-encoded-cwt-value')
    expect(mockCwtSignCallback).toHaveBeenCalledWith({
      iss: 'https://wallet.example.com',
      aud: 'https://issuer.example.com',
      nonce: 'test-nonce',
      alg: 'ES256',
    })
  })

  it('should throw if no CWT signer callback is provided', async () => {
    const callbacks: ProofOfPossessionCallbacks = {
      signCallback: vi.fn(),
    }
    await expect(
      createCwtProofOfPossession(callbacks, {
        aud: 'https://issuer.example.com',
      }),
    ).rejects.toThrow('No CWT signer callback supplied')
  })

  it('should pass optional parameters correctly', async () => {
    const cwtCallback: CWTSignerCallback = vi.fn().mockResolvedValue('cwt-result')
    const callbacks: ProofOfPossessionCallbacks = {
      signCallback: vi.fn(),
      cwtSignCallback: cwtCallback,
    }
    await createCwtProofOfPossession(callbacks, {
      aud: 'https://issuer.example.com',
      kid: 'key-id-123',
      coseKey: { kty: 2, crv: 1 },
    })
    expect(cwtCallback).toHaveBeenCalledWith(
      expect.objectContaining({
        aud: 'https://issuer.example.com',
        kid: 'key-id-123',
        coseKey: { kty: 2, crv: 1 },
      }),
    )
  })

  it('ProofOfPossession union type should discriminate on proof_type', () => {
    const jwtProof = { proof_type: 'jwt' as const, jwt: 'eyJhbGci...' }
    const cwtProof = { proof_type: 'cwt' as const, cwt: 'base64url-cwt...' }

    expect(jwtProof.proof_type).toBe('jwt')
    expect(cwtProof.proof_type).toBe('cwt')
    expect('jwt' in jwtProof).toBe(true)
    expect('cwt' in cwtProof).toBe(true)
  })
})
