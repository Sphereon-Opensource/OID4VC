import { describe, expect, it } from 'vitest'

import { createDPoP, getCreateDPoPOptions, verifyDPoP } from '../dpop'

describe('dpop', () => {
  const alg = 'HS256'
  const jwk = { kty: 'Ed25519', crv: 'Ed25519', x: '123', y: '123' }
  const jwtIssuer = { alg, jwk }
  const htm = 'POST'
  const htu = 'https://example.com/token'
  const nonce = 'nonce'
  const jwtPayloadProps = { htm, htu, nonce } as const
  const jwtHeaderProps = { alg, jwk, typ: 'dpop+jwt' }
  const unsignedDpop =
    'eyJhbGciOiJIUzI1NiIsImp3ayI6eyJrdHkiOiJFZDI1NTE5IiwiY3J2IjoiRWQyNTUxOSIsIngiOiIxMjMiLCJ5IjoiMTIzIn0sInR5cCI6ImRwb3Arand0In0.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9leGFtcGxlLmNvbS90b2tlbiIsIm5vbmNlIjoibm9uY2UiLCJpYXQiOjE3MjIzMjcxOTQsImp0aSI6Ijk4OWNiZTc4LWI1ZTYtNDViYS1iYjMzLWQ0MGE4ZGEwZjFhYSJ9'

  it('should create a dpop with valid options', async () => {
    const dpop = await createDPoP({
      jwtIssuer,
      jwtPayloadProps,
      createJwtCallback: async (dpopJwtIssuerWithContext, jwt) => {
        expect(dpopJwtIssuerWithContext.alg).toEqual(alg)
        expect(dpopJwtIssuerWithContext.jwk).toEqual(jwk)
        expect(dpopJwtIssuerWithContext.dPoPSigningAlgValuesSupported).toBeUndefined()
        expect(dpopJwtIssuerWithContext.type).toEqual('dpop')

        expect(jwt.header).toStrictEqual(jwtHeaderProps)
        expect(jwt.payload).toStrictEqual({
          ...jwtPayloadProps,
          iat: expect.any(Number),
          jti: expect.any(String),
        })

        return unsignedDpop
      },
    })

    expect(unsignedDpop).toEqual(dpop)
    expect.assertions(7)
  })

  it('should create a dpop with valid createDPoPOptions', async () => {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { htm, htu, ...rest } = jwtPayloadProps
    const options = getCreateDPoPOptions(
      {
        jwtIssuer,
        jwtPayloadProps: rest,
        createJwtCallback: async (dpopJwtIssuerWithContext, jwt) => {
          expect(dpopJwtIssuerWithContext.alg).toEqual(alg)
          expect(dpopJwtIssuerWithContext.jwk).toEqual(jwk)
          expect(dpopJwtIssuerWithContext.dPoPSigningAlgValuesSupported).toBeUndefined()
          expect(dpopJwtIssuerWithContext.type).toEqual('dpop')

          expect(jwt.header).toStrictEqual(jwtHeaderProps)
          expect(jwt.payload).toStrictEqual({
            ...jwtPayloadProps,
            iat: expect.any(Number),
            jti: expect.any(String),
          })

          return unsignedDpop
        },
      },
      htu + '?123412341#xyaksdjfaksdjf',
    )

    const dpop = await createDPoP(options)

    expect(unsignedDpop).toEqual(dpop)
    expect.assertions(7)
  })

  it('verify dpop fails if jwtVerifyCallback throws an error', async () => {
    await expect(
      verifyDPoP(
        {
          headers: { dpop: unsignedDpop },
          fullUrl: htu + '?123412341#xyaksdjfaksdjf',
          method: 'POST',
        },
        {
          jwtVerifyCallback: async () => {
            throw new Error('jwtVerifyCallback')
          },
          expectedNonce: 'nonce',
          expectAccessToken: false,
          now: 1722327194,
        },
      ),
    ).rejects.toThrow()
  })

  it('should verify a dpop with valid options', async () => {
    const dpop = await verifyDPoP(
      {
        headers: { dpop: unsignedDpop },
        fullUrl: htu + '?123412341#xyaksdjfaksdjf',
        method: 'POST',
      },
      {
        jwtVerifyCallback: async (jwtVerifier, jwt) => {
          expect(jwtVerifier.method).toEqual('jwk')
          expect(jwtVerifier.jwk).toEqual(jwk)
          expect(jwtVerifier.type).toEqual('dpop')
          expect(jwtVerifier.alg).toEqual(alg)

          expect(jwt.header).toStrictEqual(jwtHeaderProps)
          expect(jwt.payload).toStrictEqual({
            ...jwtPayloadProps,
            iat: expect.any(Number),
            jti: expect.any(String),
          })
          expect(jwt.raw).toEqual(unsignedDpop)

          return true
        },
        expectAccessToken: false,
        expectedNonce: 'nonce',
        now: 1722327194,
      },
    )
    expect(dpop).toStrictEqual(jwk)
    expect.assertions(8)
  })
})
