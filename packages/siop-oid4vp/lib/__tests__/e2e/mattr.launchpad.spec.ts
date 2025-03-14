import { SigningAlgo } from '@sphereon/oid4vc-common'
import { PresentationSignCallBackParams, PresentationSubmissionLocation } from '@sphereon/pex'
import { W3CVerifiablePresentation } from '@sphereon/ssi-types'
import * as ed25519 from '@transmute/did-key-ed25519'
import { fetch } from 'cross-fetch'
import { DIDDocument, DIDResolutionResult } from 'did-resolver'
import { importJWK, JWK, SignJWT } from 'jose'
import * as u8a from 'uint8arrays'

import { AuthorizationRequest, AuthorizationResponse, OP, PresentationDefinitionWithLocation, PresentationExchange, SupportedVersion } from '../..'
import { getCreateJwtCallback, getVerifyJwtCallback } from '../DidJwtTestUtils'

export interface InitiateOfferRequest {
  types: string[]
}

export interface InitiateOfferResponse {
  authorizeRequestUri: string
  state: string
  nonce: string
}

export const UNIT_TEST_TIMEOUT = 30000

export const VP_CREATE_URL = 'https://launchpad.mattrlabs.com/api/vp/create'

export const OPENBADGE_JWT_VC =
  'eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp3ZWI6bGF1bmNocGFkLnZpaS5lbGVjdHJvbi5tYXR0cmxhYnMuaW8jNkJoRk1DR1RKZyJ9.eyJpc3MiOiJkaWQ6d2ViOmxhdW5jaHBhZC52aWkuZWxlY3Ryb24ubWF0dHJsYWJzLmlvIiwic3ViIjoiZGlkOmtleTp6Nk1raXRHVmduTGRORlpqbUE5WEpwQThrM29lakVudU1GN205NkJEN3BaTGprWTIiLCJuYmYiOjE2OTYzNjA1MTEsImV4cCI6MTcyNzk4MjkxMSwidmMiOnsibmFtZSI6IkV4YW1wbGUgVW5pdmVyc2l0eSBEZWdyZWUiLCJkZXNjcmlwdGlvbiI6IkpGRiBQbHVnZmVzdCAzIE9wZW5CYWRnZSBDcmVkZW50aWFsIiwiY3JlZGVudGlhbEJyYW5kaW5nIjp7ImJhY2tncm91bmRDb2xvciI6IiM0NjRjNDkifSwiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL21hdHRyLmdsb2JhbC9jb250ZXh0cy92Yy1leHRlbnNpb25zL3YyIiwiaHR0cHM6Ly9wdXJsLmltc2dsb2JhbC5vcmcvc3BlYy9vYi92M3AwL2NvbnRleHQtMy4wLjIuanNvbiIsImh0dHBzOi8vcHVybC5pbXNnbG9iYWwub3JnL3NwZWMvb2IvdjNwMC9leHRlbnNpb25zLmpzb24iLCJodHRwczovL3czaWQub3JnL3ZjLXJldm9jYXRpb24tbGlzdC0yMDIwL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJPcGVuQmFkZ2VDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1raXRHVmduTGRORlpqbUE5WEpwQThrM29lakVudU1GN205NkJEN3BaTGprWTIiLCJ0eXBlIjpbIkFjaGlldmVtZW50U3ViamVjdCJdLCJhY2hpZXZlbWVudCI6eyJpZCI6Imh0dHBzOi8vZXhhbXBsZS5jb20vYWNoaWV2ZW1lbnRzLzIxc3QtY2VudHVyeS1za2lsbHMvdGVhbXdvcmsiLCJuYW1lIjoiVGVhbXdvcmsiLCJ0eXBlIjpbIkFjaGlldmVtZW50Il0sImltYWdlIjp7ImlkIjoiaHR0cHM6Ly93M2MtY2NnLmdpdGh1Yi5pby92Yy1lZC9wbHVnZmVzdC0zLTIwMjMvaW1hZ2VzL0pGRi1WQy1FRFUtUExVR0ZFU1QzLWJhZGdlLWltYWdlLnBuZyIsInR5cGUiOiJJbWFnZSJ9LCJjcml0ZXJpYSI6eyJuYXJyYXRpdmUiOiJUZWFtIG1lbWJlcnMgYXJlIG5vbWluYXRlZCBmb3IgdGhpcyBiYWRnZSBieSB0aGVpciBwZWVycyBhbmQgcmVjb2duaXplZCB1cG9uIHJldmlldyBieSBFeGFtcGxlIENvcnAgbWFuYWdlbWVudC4ifSwiZGVzY3JpcHRpb24iOiJUaGlzIGJhZGdlIHJlY29nbml6ZXMgdGhlIGRldmVsb3BtZW50IG9mIHRoZSBjYXBhY2l0eSB0byBjb2xsYWJvcmF0ZSB3aXRoaW4gYSBncm91cCBlbnZpcm9ubWVudC4ifX0sImlzc3VlciI6eyJpZCI6ImRpZDp3ZWI6bGF1bmNocGFkLnZpaS5lbGVjdHJvbi5tYXR0cmxhYnMuaW8iLCJuYW1lIjoiRXhhbXBsZSBVbml2ZXJzaXR5IiwiaWNvblVybCI6Imh0dHBzOi8vdzNjLWNjZy5naXRodWIuaW8vdmMtZWQvcGx1Z2Zlc3QtMS0yMDIyL2ltYWdlcy9KRkZfTG9nb0xvY2t1cC5wbmciLCJpbWFnZSI6Imh0dHBzOi8vdzNjLWNjZy5naXRodWIuaW8vdmMtZWQvcGx1Z2Zlc3QtMS0yMDIyL2ltYWdlcy9KRkZfTG9nb0xvY2t1cC5wbmcifX19.JDQ5kp_nvqJbL9Q8o2xIdt_r_WG0cB1o-Boy1RiDZhXRlVTgwAxvCa41OiL97VnbovN98tL7VtXbM6slAt6TBg'

export const jwk: JWK = {
  crv: 'Ed25519',
  d: 'kTRm0aONHYwNPA-w_DtjMHUIWjE3K70qgCIhWojZ0eU',
  x: 'NeA0d8sp86xRh3DczU4m5wPNIbl0HCSwOBcMN3sNmdk',
  kty: 'OKP',
}

// pub  hex: 35e03477cb29f3ac518770dccd4e26e703cd21b9741c24b038170c377b0d99d9
const hexPrivateKey = '913466d1a38d1d8c0d3c0fb0fc3b633075085a31372bbd2a8022215a88d9d1e5'

const didStr = `did:key:z6Mki5ZwZKN1dBQprfJTikUvkDxrHijiiQngkWviMF5gw2Hv`
const kid = `${didStr}#z6Mki5ZwZKN1dBQprfJTikUvkDxrHijiiQngkWviMF5gw2Hv`

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const generateCustomDid = async (opts?: { seed?: Uint8Array }): Promise<{ keys: any; didDocument: DIDDocument }> => {
  const { didDocument, keys } = await ed25519.generate(
    {
      secureRandom: () => {
        return opts?.seed ?? '913466d1a38d1d8c0d3c0fb0fc3b633075085a31372bbd2a8022215a88d9d1e5'
      },
    },
    { accept: 'application/did+json' },
  )

  return { keys, didDocument }
}

const resolve = async (didUrl: string): Promise<DIDResolutionResult> => {
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  return await didKeyResolve(didUrl, options)
}

const getResolver = () => {
  return { resolve }
}

describe('OID4VCI-Client using Mattr issuer should', () => {
  async function testWithOp(format: string | string[]) {
    const did = await generateCustomDid({ seed: u8a.fromString(hexPrivateKey, 'base16') })
    expect(did).toBeDefined()
    expect(did.didDocument).toBeDefined()

    const offer = await getOffer(format)
    const { authorizeRequestUri, state, nonce } = offer
    expect(authorizeRequestUri).toBeDefined()
    expect(state).toBeDefined()
    expect(nonce).toBeDefined()

    const correlationId = 'test'

    const op: OP = OP.builder()
      .withPresentationSignCallback(presentationSignCalback)
      .withCreateJwtCallback(getCreateJwtCallback({ alg: SigningAlgo.EDDSA, kid, did: didStr, hexPrivateKey }))
      .withVerifyJwtCallback(getVerifyJwtCallback(getResolver(), { checkLinkedDomain: 'never' }))
      .build()

    const verifiedAuthRequest = await op.verifyAuthorizationRequest(authorizeRequestUri, { correlationId })
    expect(verifiedAuthRequest).toBeDefined()
    expect(verifiedAuthRequest.presentationDefinitions).toHaveLength(1)

    const pex = new PresentationExchange({ allDIDs: [didStr], allVerifiableCredentials: [OPENBADGE_JWT_VC] })
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      verifiedAuthRequest.authorizationRequestPayload,
    )
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition)
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, [OPENBADGE_JWT_VC], presentationSignCalback, {
      presentationSubmissionLocation: PresentationSubmissionLocation.EXTERNAL,
      proofOptions: { nonce },
      holderDID: didStr,
    })

    const authResponse = await op.createAuthorizationResponse(verifiedAuthRequest, {
      issuer: didStr,
      presentationExchange: {
        verifiablePresentations: verifiablePresentationResult.verifiablePresentations,
        presentationSubmission: verifiablePresentationResult.presentationSubmission,
      },
      correlationId,
      jwtIssuer: {
        method: 'did',
        didUrl: kid,
        alg: SigningAlgo.EDDSA,
      },
    })

    expect(authResponse).toBeDefined()
    expect(authResponse.response.payload).toBeDefined()
    expect(authResponse.response.payload.presentation_submission).toBeDefined()
    expect(authResponse.response.payload.vp_token).toBeDefined()

    const result = await op.submitAuthorizationResponse(authResponse)
    expect(result.status).toEqual(200)
  }

  async function testWithPayloads(format: string | string[]) {
    const did = await generateCustomDid({ seed: u8a.fromString(hexPrivateKey, 'base16') })
    expect(did).toBeDefined()
    expect(did.didDocument).toBeDefined()

    const offer = await getOffer(format)
    const { authorizeRequestUri, state, nonce } = offer
    expect(authorizeRequestUri).toBeDefined()
    expect(state).toBeDefined()
    expect(nonce).toBeDefined()

    const correlationId = 'test'

    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(offer.authorizeRequestUri)
    const verifiedAuthRequest = await authorizationRequest.verify({
      correlationId,
      verifyJwtCallback: getVerifyJwtCallback(getResolver()),
      verification: {},
    })
    expect(verifiedAuthRequest).toBeDefined()
    expect(verifiedAuthRequest.presentationDefinitions).toHaveLength(1)

    const pex = new PresentationExchange({ allDIDs: [didStr], allVerifiableCredentials: [OPENBADGE_JWT_VC] })
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      verifiedAuthRequest.authorizationRequestPayload,
    )
    await pex.selectVerifiableCredentialsForSubmission(pd[0].definition)
    const verifiablePresentationResult = await pex.createVerifiablePresentation(pd[0].definition, [OPENBADGE_JWT_VC], presentationSignCalback, {
      presentationSubmissionLocation: PresentationSubmissionLocation.EXTERNAL,
      proofOptions: { nonce },
      holderDID: didStr,
    })

    const authResponse = await AuthorizationResponse.fromVerifiedAuthorizationRequest(
      verifiedAuthRequest,
      {
        jwtIssuer: {
          method: 'did',
          didUrl: kid,
          alg: SigningAlgo.EDDSA,
        },
        presentationExchange: {
          verifiablePresentations: verifiablePresentationResult.verifiablePresentations,
          presentationSubmission: verifiablePresentationResult.presentationSubmission,
        },
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: '913466d1a38d1d8c0d3c0fb0fc3b633075085a31372bbd2a8022215a88d9d1e5',
          did: didStr,
          kid,
          alg: SigningAlgo.EDDSA,
        }),
      },
      {
        correlationId,
        verifyJwtCallback: getVerifyJwtCallback(getResolver()),
        verification: {},
        nonce,
        state,
      },
    )

    expect(authResponse).toBeDefined()
    expect(authResponse.payload).toBeDefined()
    expect(authResponse.payload.presentation_submission).toBeDefined()
    expect(authResponse.payload.vp_token).toBeDefined()
  }

  it(
    'succeed using OpenID4VCI version 11 and ldp_vc request/responses',
    async () => {
      await testWithPayloads('OpenBadgeCredential')
    },
    UNIT_TEST_TIMEOUT,
  )
  it(
    'succeed in a full flow with the client using OpenID4VCI version 11 and jwt_vc_json',
    async () => {
      await testWithOp('OpenBadgeCredential')
    },
    UNIT_TEST_TIMEOUT,
  )
})

async function getOffer(types: string | string[]): Promise<InitiateOfferResponse> {
  const credentialOffer = await fetch(VP_CREATE_URL, {
    method: 'post',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },

    //make sure to serialize your JSON body
    body: JSON.stringify({
      types: Array.isArray(types) ? types : [types],
    }),
  })

  return (await credentialOffer.json()) as InitiateOfferResponse
}

describe('Mattr OID4VP v18 credential offer', () => {
  test('should verify using request directly', async () => {
    const offer = await getOffer('OpenBadgeCredential')
    const authorizationRequest = await AuthorizationRequest.fromUriOrJwt(offer.authorizeRequestUri)

    const verification = await authorizationRequest.verify({
      verifyJwtCallback: getVerifyJwtCallback(getResolver()),
      correlationId: 'test',
      verification: {},
    })

    expect(verification).toBeDefined()
    expect(verification.versions).toEqual([SupportedVersion.SIOPv2_D12_OID4VP_D20, SupportedVersion.SIOPv2_D12_OID4VP_D18])

    /**
     * pd value: {"id":"dae5d9b6-8145-4297-99b2-b8fcc5abb5ad","input_descriptors":[{"id":"OpenBadgeCredential","format":{"jwt_vc_json":{"alg":["EdDSA"]},"jwt_vc":{"alg":["EdDSA"]}},"constraints":{"fields":[{"path":["$.vc.type"],"filter":{"type":"array","items":{"type":"string"},"contains":{"const":"OpenBadgeCredential"}}}]}}]}
     */
  })
})

async function presentationSignCalback(args: PresentationSignCallBackParams): Promise<W3CVerifiablePresentation> {
  const importedJwk = await importJWK(jwk, 'EdDSA')
  const jwt = await new SignJWT({ vp: { ...args.presentation }, nonce: args.options.proofOptions?.nonce, iss: args.options.holderDID })
    .setProtectedHeader({
      typ: 'JWT',
      alg: 'EdDSA',
      kid,
    })
    .setIssuedAt()
    .setExpirationTime('2h')
    .sign(importedJwk)

  return jwt
}
