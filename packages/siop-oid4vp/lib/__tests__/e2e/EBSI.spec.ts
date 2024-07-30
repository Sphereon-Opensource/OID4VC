import { getResolver as getKeyResolver } from '@cef-ebsi/key-did-resolver'
// import { EbsiWallet } from '@cef-ebsi/wallet-lib';
import EbsiWallet from '@cef-ebsi/wallet-lib'
import { SigningAlgo, uuidv4 } from '@sphereon/oid4vc-common'
import { PresentationSignCallBackParams } from '@sphereon/pex'
import { parseDid, W3CVerifiablePresentation } from '@sphereon/ssi-types'
import { Resolver } from 'did-resolver'
import { importJWK, JWK, SignJWT } from 'jose'

import { OP } from '../../'
import { getCreateJwtCallback, getVerifyJwtCallback } from '../DidJwtTestUtils'

const ID_TOKEN_REQUEST_URL = 'https://api-conformance.ebsi.eu/conformance/v3/auth-mock/id_token_request'

export const UNIT_TEST_TIMEOUT = 30000
export const jwk: JWK = {
  alg: 'ES256',
  kty: 'EC',
  use: 'sig',
  crv: 'P-256',
  x: '9ggs4Cm4VXcKOePpjkL9iSyMCa22yOjbo-oUXpy-aw0',
  y: 'lEXW7b_J7lceiVEtrfptvuPeENsOJl-fhzmu654GPR8',
}
const hexPrivateKey = '47dc6ae067aa011f8574d2da7cf8c326538af08b85e6779d192a9893291c9a0a'

const nonce = uuidv4()
export const generateDid = () => {
  const did = EbsiWallet.createDid('NATURAL_PERSON', jwk)
  return did
}

const keyResolver = getKeyResolver()

const didStr = generateDid()
const kid = `${didStr}#${parseDid(didStr).id}`

describe('EBSI SIOPv2 should', () => {
  async function testWithOp() {
    const did = generateDid(/*{ seed: u8a.fromString(hexPrivateKey, 'base16') }*/)
    expect(did).toBeDefined()

    const authRequestURL = await getAuthRequestURL({ nonce })
    expect(authRequestURL).toBeDefined()
    expect(authRequestURL).toContain('openid://?state=')
    expect(authRequestURL).toContain(nonce)

    const correlationId = 'test'

    const resolver = new Resolver(keyResolver)
    const op: OP = OP.builder()
      .withPresentationSignCallback(presentationSignCalback)
      .withCreateJwtCallback(getCreateJwtCallback({ alg: SigningAlgo.ES256, kid, did: didStr, hexPrivateKey }))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver, { checkLinkedDomain: 'never' }))
      .build()

    const verifiedAuthRequest = await op.verifyAuthorizationRequest(authRequestURL, { correlationId })
    expect(verifiedAuthRequest).toBeDefined()

    const authResponse = await op.createAuthorizationResponse(verifiedAuthRequest, {
      issuer: didStr,
      correlationId,
      jwtIssuer: {
        method: 'did',
        didUrl: kid,
        alg: SigningAlgo.ES256,
      },
    })

    expect(authResponse).toBeDefined()
    expect(authResponse.response.payload).toBeDefined()
    console.log(JSON.stringify(authResponse))

    const result = await op.submitAuthorizationResponse(authResponse)
    console.log(result.statusText)
    console.log(await result.text())
    expect(result.status).toEqual(204)
  }

  it.skip(
    'succeed with an id token only',
    async () => {
      await testWithOp()
    },
    UNIT_TEST_TIMEOUT,
  )

  async function getAuthRequestURL({ nonce }: { nonce: string }): Promise<string> {
    const credentialOffer = await fetch(ID_TOKEN_REQUEST_URL, {
      method: 'post',
      headers: {
        Accept: 'text/plain',
        'Content-Type': 'application/json',
      },

      //make sure to serialize your JSON body
      body: JSON.stringify({
        nonce,
      }),
    })

    return await credentialOffer.text()
  }

  async function presentationSignCalback(args: PresentationSignCallBackParams): Promise<W3CVerifiablePresentation> {
    const importedJwk = await importJWK(jwk, 'ES256')
    const jwt = await new SignJWT({
      vp: { ...args.presentation },
      nonce: args.options.proofOptions?.nonce,
      iss: args.options.holderDID,
    })
      .setProtectedHeader({
        typ: 'JWT',
        alg: 'ES256',
        kid,
      })
      .setIssuedAt()
      .setExpirationTime('2h')
      .sign(importedJwk)

    console.log(`VP: ${jwt}`)
    return jwt
  }
})
