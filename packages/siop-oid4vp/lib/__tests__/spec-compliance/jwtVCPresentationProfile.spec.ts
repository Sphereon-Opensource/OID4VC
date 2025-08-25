import { SigningAlgo } from '@sphereon/oid4vc-common'
import * as jose from 'jose'
import { KeyLike } from 'jose'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as u8a from 'uint8arrays'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { DcqlPresentation, DcqlQuery, DcqlQueryResult, DcqlSdJwtVcCredential } from 'dcql'
import { getVerifyJwtCallback, internalSignature } from '../DidJwtTestUtils'
import { getResolver } from '../ResolverTestUtils'
import {
  AuthorizationRequest,
  AuthorizationResponse,
  IDToken,
  OP,
  PassBy,
  PresentationVerificationCallback,
  PropertyTarget,
  ResponseMode,
  ResponseType,
  RevocationVerification,
  RP,
  SupportedVersion
} from '../..'

const { fromString, toString } = u8a

let rp: RP
let op: OP

afterEach(() => {
  nock.cleanAll()
})

const presentationVerificationCallback: PresentationVerificationCallback = async () => ({ verified: true })

const verifyJwtCallback = getVerifyJwtCallback(getResolver('jwk'), {
  policies: { exp: false, iat: false, aud: false, nbf: false },
  checkLinkedDomain: 'if_present',
})

beforeEach(async () => {
  await TestVectors.init()

  TestVectors.mockDID(TestVectors.issuerDID, TestVectors.issuerKID, TestVectors.issuerJwk)
  TestVectors.mockDID(TestVectors.holderDID, TestVectors.holderKID, TestVectors.holderJwk)
  TestVectors.mockDID(TestVectors.verifierDID, TestVectors.verifierKID, TestVectors.verifierJwk)

  rp = RP.builder({ requestVersion: SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1 })
    .withResponseType(ResponseType.ID_TOKEN, PropertyTarget.REQUEST_OBJECT)
    .withClientId(TestVectors.issuerDID, PropertyTarget.REQUEST_OBJECT)
    .withScope('openid', PropertyTarget.REQUEST_OBJECT)
    .withResponseMode(ResponseMode.POST, PropertyTarget.REQUEST_OBJECT)
    .withClientMetadata(
      {
        passBy: PassBy.VALUE,
        logo_uri: 'https://example.com/verifier-icon.png',
        tos_uri: 'https://example.com/verifier-info',
        clientName: 'Example Verifier',
        vpFormatsSupported: {
          jwt_vc: {
            alg: ['ES256K', 'ECDSA'],
          },
          jwt_vp: {
            alg: ['ES256K', 'ECDSA'],
          },
        },
        subject_syntax_types_supported: ['did:jwk'],
      },
      PropertyTarget.REQUEST_OBJECT,
    )
    .withRedirectUri('https://example.com/siop-response', PropertyTarget.REQUEST_OBJECT)
    .withRequestBy(PassBy.REFERENCE, TestVectors.request_uri)
    .withCreateJwtCallback(internalSignature(TestVectors.verifierHexPrivateKey, TestVectors.verifierDID, TestVectors.verifierKID, SigningAlgo.ES256))
    .withVerifyJwtCallback(verifyJwtCallback)
    .build()

  op = OP.builder()
    .withCreateJwtCallback(internalSignature(TestVectors.holderHexPrivateKey, TestVectors.holderDID, TestVectors.holderKID, SigningAlgo.ES256))
    .withVerifyJwtCallback(verifyJwtCallback)
    .addSupportedVersion(SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1)
    .build()
})

describe('RP using test vectors', () => {
  it('should create matching auth request and URI', async () => {
    const authRequest = await createAuthRequest()
    expect(authRequest.requestObject?.getPayload()).toMatchObject({
      response_type: 'id_token',
      nonce: '40252afc-6a82-4a2e-905f-e41f122ef575',
      client_id: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0',
      response_mode: 'post',
      scope: 'openid',
      claims: {
        vp_token: {
          dcql_query: TestVectors.parsedDcqlQuery //JSON.stringify(
        },
      },
      registration: {
        logo_uri: 'https://example.com/verifier-icon.png',
        tos_uri: 'https://example.com/verifier-info',
        client_name: 'Example Verifier',
        vp_formats: {
          jwt_vc: {
            alg: ['ES256K', 'ECDSA'],
          },
          jwt_vp: {
            alg: ['ES256K', 'ECDSA'],
          },
        },
        subject_syntax_types_supported: ['did:jwk'],
      },
      state: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
      redirect_uri: 'https://example.com/siop-response'
    })
  })

  it('should re-create uri', async () => {
    const authRequest = await createAuthRequest()
    const uri = await authRequest.uri()
    expect(uri.encodedUri).toEqual(
        'openid-vc://?request_uri=https%3A%2F%2Fexample%2Fservice%2Fapi%2Fv1%2Fpresentation-request%2F649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9&client_id=did%3Ajwk%3AeyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0'
    )
  })

  it('should get presentation definition', async () => {
    const authRequest = await createAuthRequest()
    const dcql = await authRequest.getDcqlQuery()
    expect(dcql).toBeDefined()
  })

  it('should decode id token jwt', async () => {
    const idToken = await IDToken.fromIDToken(TestVectors.idTokenJwt)
    expect(idToken).toBeDefined()
    const payload = idToken.payload()
    expect(payload).toEqual(TestVectors.idTokenPayload)
    expect(
      await idToken.verify({
        correlationId: '1234',
        audience: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0',
        verifyJwtCallback: verifyJwtCallback,
        verification: {
          presentationVerificationCallback,
        },
      }),
    ).toBeTruthy()
  })

  it('should decode auth response', async () => {
    const authorizationResponse = await AuthorizationResponse.fromPayload(TestVectors.authorizationResponsePayload)
    expect(authorizationResponse).toBeDefined()
    expect(authorizationResponse.payload).toEqual(TestVectors.authorizationResponsePayload)
    expect(authorizationResponse.idToken?.payload()).toEqual(TestVectors.idTokenPayload)
    expect(
      await authorizationResponse.idToken?.verify({
        verifyJwtCallback: verifyJwtCallback,
        correlationId: '1234',
        audience: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0',
        verification: {
          presentationVerificationCallback,
          revocationOpts: {
            revocationVerification: RevocationVerification.NEVER,
          },
        },
      }),
    ).toBeTruthy()

    const authRequest = await createAuthRequest()
    const dcqlQuery = await authRequest.getDcqlQuery()

    // Will throw an error because the path_nested is actually wrong. Should be $.vp.verifiableCredential[0], but is $.verifiableCredential[0]
    await expect(
      authorizationResponse.verify({
        correlationId: '1234',
        verifyJwtCallback: verifyJwtCallback,
        audience: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0',
        verification: {
          presentationVerificationCallback,
          revocationOpts: {
            revocationVerification: RevocationVerification.NEVER,
          },
        },
        dcqlQuery,
      }),
    ).rejects.toThrowError()
  })
})

describe('OP using test vectors', () => {
  it('should import auth request and be able to provide the auth request unaltered', async () => {
    nock('https://example').get('/service/api/v1/presentation-request/649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9').reply(200, TestVectors.requestObjectJwt) // TODO results in prefix did, which might makes sense, but should be prefixed with decentralized-identifier
    const result = await op.verifyAuthorizationRequest(TestVectors.auth_request, {
      verification: {},
    })
    expect(result).toBeDefined()
  })

  // Disabled for now as the value for the path_nested in the id token is actually invalid
  it.skip('should use test vector auth response', async () => {
    const authorizationResponse = await AuthorizationResponse.fromPayload(TestVectors.authorizationResponsePayload)

    expect(authorizationResponse.payload.vp_token).toBeDefined()
    expect(authorizationResponse.payload.id_token).toBeDefined()
    expect(authorizationResponse.idToken?.payload()).toEqual({
      _vp_token: {
        dcql_query: JSON.stringify(TestVectors.parsedDcqlQuery),
      },
      aud: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0',
      exp: 1674786463,
      iat: 1674772063,
      iss: 'https://self-issued.me/v2/openid-vc',
      jti: '0f5dafed-0d82-43b1-af79-40440e3f1366',
      nonce: '40252afc-6a82-4a2e-905f-e41f122ef575',
      sub: "did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0",
    })

    await rp.verifyAuthorizationResponse(TestVectors.authorizationResponsePayload, {
      audience: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0',
      verification: {
        revocationOpts: {
          revocationVerification: RevocationVerification.NEVER,
        },
        presentationVerificationCallback,
      },
      dcqlQuery: TestVectors.parsedDcqlQuery,
    })

    nock('https://example', {}).post('/resp').reply(200, {})
    await op.submitAuthorizationResponse({
      response: authorizationResponse,
      correlationId: '12345',
      responseURI: 'https://example/resp',
    })
  })

  it('should create auth response', async () => {
    nock('https://example')
      .get('/service/api/v1/presentation-request/649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9')
      .times(1)
      .reply(200, TestVectors.requestObjectJwt)
    const result = await op.verifyAuthorizationRequest(TestVectors.auth_request, {
      verification: {},
    })

    const sdjwt = {
      compactJwtVc:
          'eyJ0eXAiOiJ2YytzZC1qd3QiLCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lTMGRwYzNodlUzaDJhVzB4YTFOSU1XSnROMnhmUkhCeVIyczNZa2RrWkVaYVdXWnRjVXB1VjJWb1NTSXNJbmtpT2lKYVEzQldUVVZSTkhsNGNUSlZiVGRDVGpoSVQyNUdlamszTTFBMFVUQlVkbmRuZVhWUlgyRmlURlZWSW4wIzAiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lXRkpXUVhsNVJIQldNbXBNTm5oNlUwSktZM1JIZW0xS1pqbFFlV0Z4WHpNdFRVeHJlR0ZoUlRBNFRTSXNJbmtpT2lKQ1NtOUtWM05WYTBaQlUyVlRZMmx4VDFsNVNWTTBZMFpoZVU4emFHaEJTalZaYjJ0dU9IcFRTVEZuSW4wIzAiLCJpc3MiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lTMGRwYzNodlUzaDJhVzB4YTFOSU1XSnROMnhmUkhCeVIyczNZa2RrWkVaYVdXWnRjVXB1VjJWb1NTSXNJbmtpT2lKYVEzQldUVVZSTkhsNGNUSlZiVGRDVGpoSVQyNUdlamszTTFBMFVUQlVkbmRuZVhWUlgyRmlURlZWSW4wIzAiLCJpYXQiOjE3MzQ0NTgwNDIsInZjdCI6InVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSIsIl9zZCI6WyIwWWdpR25hck1LSERnVWx1QktteGdRZUJ4OF8xazMwd3NSRVN1X2t1Y0JFIiwiNEpwU2JzUEsxZndUQzRhR24zZ0hXb1BkVEJrMExOTWZMOEJXeEIxZ1JPWSIsIjRpZmplQUZveUEyQmc0STVNWEFrMVlyc1AtUVBQQXRnZGlHY0RMQTZiTFEiLCJBdTFjdURISUNISE1jUjZxM2R3d1pHbHp5dzMwSXhvTGVhWlNxRktEbmo4IiwiQ0QxbWxOY19VaVBoQUp6YkJveTVMY3dtekFNZTM3d0VLZF9iMTB6QTNxNCIsInFwZ1FOUVRac0VJWHdxUk9fT24xdUVCSVVNODBTcTJLR2tlN0JSU2N0WHciXSwiX3NkX2FsZyI6IlNIQS0yNTYifQ.P84d0CoS4M-zQ29l3S97RMatfJMYkoTgR5EqSMTdYlZAMp4e8iiuz2PXQMfJ-_undCvg4SRXxDACGiLL3Tt7Bw~WyJlNTFiNWI2NS0wNzM3LTQ0MjQtYTUxYS1jNGYzZGNlZGFmMmYiLCJnaXZlbl9uYW1lIiwiSm9obiJd~WyIxM2I1NDIwNi1kYWQ3LTQ3N2UtODYyZC03N2ZiMTQ1MDE5NjUiLCJmYW1pbHlfbmFtZSIsIkRvZSJd~WyJkMmQxNjg3Zi04ZmY4LTRlOTMtYWJjYi1hYTNlNGVjYzY0ZTMiLCJlbWFpbCIsImpvaG5kZW9AZXhhbXBsZS5jb20iXQ~WyIyZDA4YTk2YS03YzYwLTQ3NDEtYTI5YS00ZjBjYTFlNGQ3M2IiLCJwaG9uZSIsIisxLTIwMi01NTUtMDEwMSJd~WyI2YjVkN2FmOS01ZmIxLTQzNTEtYWM1ZS1hMzA1YTBkNjU0ZDUiLCJhZGRyZXNzIix7InN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsImNvdW50cnkiOiJVUyJ9XQ~WyI5MmYzY2M5ZC0yMjQ2LTRiODQtYTk5OS0xYmQyM2U0OGQ0MGEiLCJiaXJ0aGRhdGUiLCIxOTQwLTAxLTAxIl0~',
      decodedPayload: {
        header: {
          typ: 'dc+sd-jwt',
          kid: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiS0dpc3hvU3h2aW0xa1NIMWJtN2xfRHByR2s3YkdkZEZaWWZtcUpuV2VoSSIsInkiOiJaQ3BWTUVRNHl4cTJVbTdCTjhIT25Gejk3M1A0UTBUdndneXVRX2FiTFVVIn0#0',
          alg: 'ES256',
        },
        payload: {
          sub: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiWFJWQXl5RHBWMmpMNnh6U0JKY3RHem1KZjlQeWFxXzMtTUxreGFhRTA4TSIsInkiOiJCSm9KV3NVa0ZBU2VTY2lxT1l5SVM0Y0ZheU8zaGhBSjVZb2tuOHpTSTFnIn0#0',
          iss: 'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiS0dpc3hvU3h2aW0xa1NIMWJtN2xfRHByR2s3YkdkZEZaWWZtcUpuV2VoSSIsInkiOiJaQ3BWTUVRNHl4cTJVbTdCTjhIT25Gejk3M1A0UTBUdndneXVRX2FiTFVVIn0#0',
          iat: 1734458042,
          vct: 'urn:eu.europa.ec.eudi:pid:1',
          given_name: 'John',
          email: 'johndeo@example.com',
          birthdate: '1940-01-01',
          phone: '+1-202-555-0101',
          address: {
            street_address: '123 Main St',
            locality: 'Anytown',
            region: 'Anystate',
            country: 'US',
          },
          family_name: 'Doe',
        },
        kb: undefined,
      },
    }

    const vc = {
      credential_format: 'dc+sd-jwt',
      vct: sdjwt.decodedPayload.payload.vct,
      claims: sdjwt.decodedPayload.payload,
      cryptographic_holder_binding: true
    } satisfies DcqlSdJwtVcCredential

    const dcqlQueryResult: DcqlQueryResult = DcqlQuery.query(TestVectors.parsedDcqlQuery, [vc])

    const presentation: DcqlPresentation.Output = {}
    for (const [key, value] of Object.entries(dcqlQueryResult.credential_matches)) {
      if (value.success) {
        presentation[key] = sdjwt.compactJwtVc
      }
    }

    const dcqlPresentation = DcqlPresentation.parse(presentation)

    await op.createAuthorizationResponse(result, {
      dcqlResponse: {
        dcqlPresentation
      }
    })
  })
})

async function createAuthRequest(): Promise<AuthorizationRequest> {
  return await rp.createAuthorizationRequest({
    correlationId: '1234',
    nonce: { propertyValue: '40252afc-6a82-4a2e-905f-e41f122ef575', targets: PropertyTarget.REQUEST_OBJECT },
    state: { propertyValue: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9', targets: PropertyTarget.REQUEST_OBJECT },
    jwtIssuer: { method: 'did', alg: SigningAlgo.ES256, didUrl: TestVectors.verifierKID },
    claims: {
      propertyValue: {
        vp_token: {
          dcql_query: TestVectors.parsedDcqlQuery, //JSON.stringify(
        },
      },
      targets: PropertyTarget.REQUEST_OBJECT,
    },
  })
}

class TestVectors {
  public static issuerDID =
    'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0'
  public static issuerKID = `${TestVectors.issuerDID}#0`
  public static issuerJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
  }
  public static issuerKey: KeyLike
  public static issuerPrivateKey: string
  public static issuerPublicKey: string
  public static issuerHexPrivateKey: string

  public static holderJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
  }
  public static holderDID =
    'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0'
  public static holderKID = `${TestVectors.holderDID}#0`
  public static holderKey: KeyLike
  public static holderPrivateKey: string
  public static holderPublicKey: string
  public static holderHexPrivateKey: string

  public static verifierJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
    d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
  }
  public static verifierDID =
    'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0'
  public static verifierKID = `${TestVectors.verifierDID}#0`
  public static verifierKey: jose.KeyLike | Uint8Array
  public static verifierPrivateKey: string
  public static verifierPublicKey: string
  public static verifierHexPrivateKey: string

  public static async init() {
    TestVectors.issuerKey = (await jose.importJWK(TestVectors.issuerJwk, 'EcDSA', true)) as KeyLike
    TestVectors.issuerPrivateKey = toString(fromString(TestVectors.issuerJwk.d, 'base64url'), 'hex')
    TestVectors.issuerPublicKey = toString(fromString(TestVectors.issuerJwk.x, 'base64url'), 'hex')
    TestVectors.issuerHexPrivateKey = TestVectors.issuerPrivateKey

    TestVectors.holderKey = (await jose.importJWK(TestVectors.holderJwk, 'EcDSA', true)) as KeyLike
    TestVectors.holderPrivateKey = toString(fromString(TestVectors.holderJwk.d, 'base64url'), 'hex')
    TestVectors.holderPublicKey = toString(fromString(TestVectors.holderJwk.x, 'base64url'), 'hex')
    TestVectors.holderHexPrivateKey = TestVectors.holderPrivateKey

    TestVectors.verifierKey = (await jose.importJWK(TestVectors.verifierJwk, 'EcDSA', true)) as KeyLike
    TestVectors.verifierPrivateKey = toString(fromString(TestVectors.verifierJwk.d, 'base64url'), 'hex')
    TestVectors.verifierPublicKey = toString(fromString(TestVectors.verifierJwk.x, 'base64url'), 'hex')
    TestVectors.verifierHexPrivateKey = TestVectors.verifierPrivateKey
  }

  public static auth_request = 'openid4vp://?request_uri=https://example/service/api/v1/presentation-request/649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9' //openid-vc
  public static request_uri = 'https://example/service/api/v1/presentation-request/649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9'

  public static idTokenJwt =
    //'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAjMCJ9.eyJfdnBfdG9rZW4iOnsiZGNxbF9xdWVyeSI6IntcImNyZWRlbnRpYWxzXCI6W3tcImlkXCI6XCJWZXJpZmllZEVtcGxveWVlVkNcIixcInJlcXVpcmVfY3J5cHRvZ3JhcGhpY19ob2xkZXJfYmluZGluZ1wiOnRydWUsXCJtdWx0aXBsZVwiOmZhbHNlLFwiZm9ybWF0XCI6XCJkYytzZC1qd3RcIixcImNsYWltc1wiOlt7XCJwYXRoXCI6W1wibGljZW5zZVwiLFwibnVtYmVyXCJdfSx7XCJwYXRoXCI6W1widXNlclwiLFwibmFtZVwiXX1dLFwibWV0YVwiOntcInZjdF92YWx1ZXNcIjpbXCJodHRwczovL2hpZ2gtYXNzdXJhbmNlLmNvbS9WZXJpZmllZEVtcGxveWVlVkNcIl19fV19In0sImF1ZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAiLCJleHAiOjE2NzQ3ODY0NjMsImlhdCI6MTY3NDc3MjA2MywiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92Mi9vcGVuaWQtdmMiLCJqdGkiOiIwZjVkYWZlZC0wZDgyLTQzYjEtYWY3OS00MDQ0MGUzZjEzNjYiLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsInN1YiI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAifQ.S2jEDRs4JRzgeGFj6R-FPeXUNGG4n9GpcY7M_IRPbVViXLgbIbfR5t35T0WC5xJOUTM5CeNQC3PlWeYXBKZpPA'
    'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAjMCJ9.eyJfdnBfdG9rZW4iOnsiZGNxbF9xdWVyeSI6eyJjcmVkZW50aWFscyI6W3siaWQiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJyZXF1aXJlX2NyeXB0b2dyYXBoaWNfaG9sZGVyX2JpbmRpbmciOnRydWUsIm11bHRpcGxlIjpmYWxzZSwiZm9ybWF0IjoiZGMrc2Qtand0IiwiY2xhaW1zIjpbeyJwYXRoIjpbImxpY2Vuc2UiLCJudW1iZXIiXX0seyJwYXRoIjpbInVzZXIiLCJuYW1lIl19XSwibWV0YSI6eyJ2Y3RfdmFsdWVzIjpbImh0dHBzOi8vaGlnaC1hc3N1cmFuY2UuY29tL1ZlcmlmaWVkRW1wbG95ZWVWQyJdfX1dfX0sImF1ZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAiLCJleHAiOjE2NzQ3ODY0NjMsImlhdCI6MTY3NDc3MjA2MywiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92Mi9vcGVuaWQtdmMiLCJqdGkiOiIwZjVkYWZlZC0wZDgyLTQzYjEtYWY3OS00MDQ0MGUzZjEzNjYiLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsInN1YiI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAifQ.J5sHXZdWJnJWq1hs0JcoXNUAMjNPJMmNuwXffEag7CWOY0Rl-FG2hOJEZbQ3-Mp6N0p3vxxN0vWpLRUxRRfmwg'

  public static dcqlQuery = { // TODO
    credentials: [
      {
        id: 'VerifiedEmployeeVC',
        format: 'dc+sd-jwt',
        meta: {
          vct_values: ['https://high-assurance.com/VerifiedEmployeeVC'],
        },
        claims: [{ path: ['license', 'number'] }, { path: ['user', 'name'] }],
      },
    ],
  } satisfies DcqlQuery.Input
  public static parsedDcqlQuery = DcqlQuery.parse(this.dcqlQuery)

  public static idTokenPayload = {
    sub: "did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0",
    aud: "did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0",
    iss: 'https://self-issued.me/v2/openid-vc',
    exp: 1674786463,
    iat: 1674772063,
    nonce: '40252afc-6a82-4a2e-905f-e41f122ef575',
    jti: '0f5dafed-0d82-43b1-af79-40440e3f1366',
    _vp_token: {
      dcql_query: TestVectors.parsedDcqlQuery //JSON.stringify(
    }
  }

  public static requestObjectJwt =
    //'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAjMCJ9.eyJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsImNsaWVudF9pZCI6ImRlY2VudHJhbGl6ZWRfaWRlbnRpZmllcjpkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2laamd6VDBvelJESjRSakZDWnpoMmRXSTVkRXhsTVdkSVRYcFdOelpsT0ZSMWN6bDFVRWgyVWxaRlZTSXNJbmtpT2lKNFgwWkZlbEoxT1cwek5raE1UbDkwZFdVMk5UbE1UbkJZVnpad1EzbFRkR2xyV1dwTFNWZEpOV0V3SW4wIiwicmVzcG9uc2VfbW9kZSI6InBvc3QiLCJuYmYiOjE2NzQ3NzIwNjMsInNjb3BlIjoib3BlbmlkIiwiY2xhaW1zIjp7InZwX3Rva2VuIjp7ImRjcWxfcXVlcnkiOiJ7XCJjcmVkZW50aWFsc1wiOlt7XCJpZFwiOlwiVmVyaWZpZWRFbXBsb3llZVZDXCIsXCJyZXF1aXJlX2NyeXB0b2dyYXBoaWNfaG9sZGVyX2JpbmRpbmdcIjp0cnVlLFwibXVsdGlwbGVcIjpmYWxzZSxcImZvcm1hdFwiOlwidmMrc2Qtand0XCIsXCJjbGFpbXNcIjpbe1wicGF0aFwiOltcImxpY2Vuc2VcIixcIm51bWJlclwiXX0se1wicGF0aFwiOltcInVzZXJcIixcIm5hbWVcIl19XSxcIm1ldGFcIjp7XCJ2Y3RfdmFsdWVzXCI6W1wiaHR0cHM6Ly9oaWdoLWFzc3VyYW5jZS5jb20vVmVyaWZpZWRFbXBsb3llZVZDXCJdfX1dfSJ9fSwicmVnaXN0cmF0aW9uIjp7ImNsaWVudF9uYW1lIjoiRXhhbXBsZSBWZXJpZmllciIsInRvc191cmkiOiJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyLWluZm8iLCJsb2dvX3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdmVyaWZpZXItaWNvbi5wbmciLCJzdWJqZWN0X3N5bnRheF90eXBlc19zdXBwb3J0ZWQiOlsiZGlkOmp3ayJdLCJ2cF9mb3JtYXRzIjp7Imp3dF92cCI6eyJhbGciOlsiRVMyNTZLIiwiRUNEU0EiXX0sImp3dF92YyI6eyJhbGciOlsiRVMyNTZLIiwiRUNEU0EiXX19fSwic3RhdGUiOiI2NDlkOGMzYy1mNWFjLTQxYmQtOWMxOS01ODA0ZWExYjhmZTkiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2V4YW1wbGUuY29tL3Npb3AtcmVzcG9uc2UiLCJleHAiOjE2NzQ3NzU2NjMsImlhdCI6MTY3NDc3MjA2MywianRpIjoiZjBlNmRjZjUtM2ZlNi00NTA3LWFkYzktYjQ5NmRhZjM0NTEyIiwiaXNzIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmlJc0luVnpaU0k2SW5OcFp5SXNJbXQwZVNJNklrVkRJaXdpWTNKMklqb2lVQzB5TlRZaUxDSjRJam9pWmpnelQwb3pSREo0UmpGQ1p6aDJkV0k1ZEV4bE1XZElUWHBXTnpabE9GUjFjemwxVUVoMlVsWkZWU0lzSW5raU9pSjRYMFpGZWxKMU9XMHpOa2hNVGw5MGRXVTJOVGxNVG5CWVZ6WndRM2xUZEdscldXcExTVmRKTldFd0luMCJ9.JU7IVdbbQDIdBDZRT2N9zkVhULa5VJadpsJliO6sEc1xN0pBN1WK377eZOPbbtyQ12GZ5C0TKZWU1l9jt_sfug'
    'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAjMCJ9.eyJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsImNsaWVudF9pZCI6ImRlY2VudHJhbGl6ZWRfaWRlbnRpZmllcjpkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2laamd6VDBvelJESjRSakZDWnpoMmRXSTVkRXhsTVdkSVRYcFdOelpsT0ZSMWN6bDFVRWgyVWxaRlZTSXNJbmtpT2lKNFgwWkZlbEoxT1cwek5raE1UbDkwZFdVMk5UbE1UbkJZVnpad1EzbFRkR2xyV1dwTFNWZEpOV0V3SW4wIiwicmVzcG9uc2VfbW9kZSI6InBvc3QiLCJuYmYiOjE2NzQ3NzIwNjMsInNjb3BlIjoib3BlbmlkIiwiY2xhaW1zIjp7InZwX3Rva2VuIjp7ImRjcWxfcXVlcnkiOnsiY3JlZGVudGlhbHMiOlt7ImlkIjoiVmVyaWZpZWRFbXBsb3llZVZDIiwicmVxdWlyZV9jcnlwdG9ncmFwaGljX2hvbGRlcl9iaW5kaW5nIjp0cnVlLCJtdWx0aXBsZSI6ZmFsc2UsImZvcm1hdCI6InZjK3NkLWp3dCIsImNsYWltcyI6W3sicGF0aCI6WyJsaWNlbnNlIiwibnVtYmVyIl19LHsicGF0aCI6WyJ1c2VyIiwibmFtZSJdfV0sIm1ldGEiOnsidmN0X3ZhbHVlcyI6WyJodHRwczovL2hpZ2gtYXNzdXJhbmNlLmNvbS9WZXJpZmllZEVtcGxveWVlVkMiXX19XX19fSwicmVnaXN0cmF0aW9uIjp7ImNsaWVudF9uYW1lIjoiRXhhbXBsZSBWZXJpZmllciIsInRvc191cmkiOiJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyLWluZm8iLCJsb2dvX3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdmVyaWZpZXItaWNvbi5wbmciLCJzdWJqZWN0X3N5bnRheF90eXBlc19zdXBwb3J0ZWQiOlsiZGlkOmp3ayJdLCJ2cF9mb3JtYXRzIjp7Imp3dF92cCI6eyJhbGciOlsiRVMyNTZLIiwiRUNEU0EiXX0sImp3dF92YyI6eyJhbGciOlsiRVMyNTZLIiwiRUNEU0EiXX19fSwic3RhdGUiOiI2NDlkOGMzYy1mNWFjLTQxYmQtOWMxOS01ODA0ZWExYjhmZTkiLCJyZWRpcmVjdF91cmkiOiJodHRwczovL2V4YW1wbGUuY29tL3Npb3AtcmVzcG9uc2UiLCJleHAiOjE2NzQ3NzU2NjMsImlhdCI6MTY3NDc3MjA2MywianRpIjoiZjBlNmRjZjUtM2ZlNi00NTA3LWFkYzktYjQ5NmRhZjM0NTEyIiwiaXNzIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmlJc0luVnpaU0k2SW5OcFp5SXNJbXQwZVNJNklrVkRJaXdpWTNKMklqb2lVQzB5TlRZaUxDSjRJam9pWmpnelQwb3pSREo0UmpGQ1p6aDJkV0k1ZEV4bE1XZElUWHBXTnpabE9GUjFjemwxVUVoMlVsWkZWU0lzSW5raU9pSjRYMFpGZWxKMU9XMHpOa2hNVGw5MGRXVTJOVGxNVG5CWVZ6WndRM2xUZEdscldXcExTVmRKTldFd0luMCJ9.zU-sausFlBk_4VxqwgViho7_ZUsmiIAADn6WLME-xOqBvv71uzx44QVq_OBBQNZCXsRlTJYfUV_rbXZVk5U1HQ'

  public static requestObjectPayload =
    '  {\n' +
    '    "kid" : "did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0#0",\n' +
    '    "typ" : "JWT",\n' +
    '    "alg" : "ES256"\n' +
    '  }.\n' +
    '  {\n' +
    '    "response_type" : "id_token",\n' +
    '    "nonce" : "40252afc-6a82-4a2e-905f-e41f122ef575",\n' +
    '    "client_id" : "did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiZjgzT0ozRDJ4RjFCZzh2dWI5dExlMWdITXpWNzZlOFR1czl1UEh2UlZFVSIsInkiOiJ4X0ZFelJ1OW0zNkhMTl90dWU2NTlMTnBYVzZwQ3lTdGlrWWpLSVdJNWEwIn0",\n' +
    '    "response_mode" : "post",\n' +
    '    "nbf" : 1674772063,\n' +
    '    "scope" : "openid",\n' +
    '    "claims" : {\n' +
    '      "vp_token" : {\n' +
    '        "dcql_query": {\n' +
    '         "credentials": [ \n' +
    '           { "id":"VerifiedEmployeeVC", \n' +
    '             "require_cryptographic_holder_binding": true, \n' +
    '             "multiple": false, \n' +
    '             "format": "dc+sd-jwt", \n' +
    '             "claims": [ \n' +
    '               { "path": ["license","number"] }, \n' +
    '               { "path": ["user","name"] } \n' +
    '             ], \n' +
    '             "meta": { \n' +
    '               "vct_values": ["https://high-assurance.com/VerifiedEmployeeVC"]' +
    '              } \n' +
    '            } \n' +
    '           ] \n' +
    '          } \n' +
    '        } \n' +
    '       }\n' +
    '    },\n' +
    '    "registration" : {\n' +
    '      "logo_uri" : "https://example.com/verifier-icon.png",\n' +
    '      "tos_uri" : "https://example.com/verifier-info",\n' +
    '      "client_name" : "Example Verifier",\n' +
    '      "vp_formats" : {\n' +
    '        "jwt_vc" : {\n' +
    '          "alg" : [ "ES256K", "ECDSA" ]\n' +
    '        },\n' +
    '        "jwt_vp" : {\n' +
    '          "alg" : [ "ES256K", "ECDSA" ]\n' +
    '        }\n' +
    '      },\n' +
    '      "subject_syntax_types_supported" : [ "did:jwk" ]\n' +
    '    },\n' +
    '    "state" : "649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9",\n' +
    '    "redirect_uri" : "https://example.com/siop-response",\n' +
    '    "exp" : 1674775663,\n' +
    '    "iat" : 1674772063,\n' +
    '    "jti" : "f0e6dcf5-3fe6-4507-adc9-b496daf34512"\n' +
    '  }.\n' +
    '  [withSignature]\n'

  public static authorizationResponsePayload = {
    state: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
    id_token:
      //'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAjMCJ9.eyJfdnBfdG9rZW4iOnsiZGNxbF9xdWVyeSI6IntcImNyZWRlbnRpYWxzXCI6W3tcImlkXCI6XCJWZXJpZmllZEVtcGxveWVlVkNcIixcInJlcXVpcmVfY3J5cHRvZ3JhcGhpY19ob2xkZXJfYmluZGluZ1wiOnRydWUsXCJtdWx0aXBsZVwiOmZhbHNlLFwiZm9ybWF0XCI6XCJkYytzZC1qd3RcIixcImNsYWltc1wiOlt7XCJwYXRoXCI6W1wibGljZW5zZVwiLFwibnVtYmVyXCJdfSx7XCJwYXRoXCI6W1widXNlclwiLFwibmFtZVwiXX1dLFwibWV0YVwiOntcInZjdF92YWx1ZXNcIjpbXCJodHRwczovL2hpZ2gtYXNzdXJhbmNlLmNvbS9WZXJpZmllZEVtcGxveWVlVkNcIl19fV19In0sImF1ZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAiLCJleHAiOjE2NzQ3ODY0NjMsImlhdCI6MTY3NDc3MjA2MywiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92Mi9vcGVuaWQtdmMiLCJqdGkiOiIwZjVkYWZlZC0wZDgyLTQzYjEtYWY3OS00MDQ0MGUzZjEzNjYiLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsInN1YiI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAifQ.S2jEDRs4JRzgeGFj6R-FPeXUNGG4n9GpcY7M_IRPbVViXLgbIbfR5t35T0WC5xJOUTM5CeNQC3PlWeYXBKZpPA',
      'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAjMCJ9.eyJfdnBfdG9rZW4iOnsiZGNxbF9xdWVyeSI6eyJjcmVkZW50aWFscyI6W3siaWQiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJyZXF1aXJlX2NyeXB0b2dyYXBoaWNfaG9sZGVyX2JpbmRpbmciOnRydWUsIm11bHRpcGxlIjpmYWxzZSwiZm9ybWF0IjoiZGMrc2Qtand0IiwiY2xhaW1zIjpbeyJwYXRoIjpbImxpY2Vuc2UiLCJudW1iZXIiXX0seyJwYXRoIjpbInVzZXIiLCJuYW1lIl19XSwibWV0YSI6eyJ2Y3RfdmFsdWVzIjpbImh0dHBzOi8vaGlnaC1hc3N1cmFuY2UuY29tL1ZlcmlmaWVkRW1wbG95ZWVWQyJdfX1dfX0sImF1ZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAiLCJleHAiOjE2NzQ3ODY0NjMsImlhdCI6MTY3NDc3MjA2MywiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92Mi9vcGVuaWQtdmMiLCJqdGkiOiIwZjVkYWZlZC0wZDgyLTQzYjEtYWY3OS00MDQ0MGUzZjEzNjYiLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsInN1YiI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVpqZ3pUMG96UkRKNFJqRkNaemgyZFdJNWRFeGxNV2RJVFhwV056WmxPRlIxY3psMVVFaDJVbFpGVlNJc0lua2lPaUo0WDBaRmVsSjFPVzB6TmtoTVRsOTBkV1UyTlRsTVRuQllWelp3UTNsVGRHbHJXV3BMU1ZkSk5XRXdJbjAifQ.J5sHXZdWJnJWq1hs0JcoXNUAMjNPJMmNuwXffEag7CWOY0Rl-FG2hOJEZbQ3-Mp6N0p3vxxN0vWpLRUxRRfmwg',
    vp_token:
      'eyJraWQiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJhdWQiOiJkaWQ6aW9uOkVpQldlOVJ0SFQ3VlotSnVmZjhPbm5KQXlGSnRDb2tjWUh4MUNRa0Z0cGw3cHc6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklrTmZUMVZLZUVnMmFVbGpRelpZWkU1b04wcHRReTFVU0ZoQlZtRllibloxT1U5RlJWbzRkSEU1VGtraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVOWVRrSnFTV1pNVkdaT1YwTkhNRlEyTTJWYVltSkVaRlpvU21KVVRqZ3RTbVpsYVV4NGRXMW9aVzUzSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbENaVlo1UlhCRGIwTlBlWEo2VkRoRFNIbHZRVzFhY1UxQ1QxbzBWVFpxY20xc2RVdDFTamx4UzBwa1p5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFuaGtjSGx5YW1sVlNGWjFha05SV1RCS01raEJVRkZZWm5Od1dGQktZV2x1VjIxbVYzUk5jRmhuZUZFaWZYMCIsImlzcyI6ImRpZDppb246RWlBZU02Tm85a2Rwb3M2X2VoQlVEaDRSSU5ZNFVTRE1oLVFkV2tzbXNJM1drQTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SW5jd05rOVdOMlUyYmxSMWNuUTJSemxXY0ZaWWVFbDNXVzU1YW1aMWNIaGxSM2xMUWxNdFlteHhkbWNpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVUZTTkdSVlFteHFOV05HYTNkTWRrcFRXVVl6VkV4akxWODFNV2hEWDJ4WmFHeFhaa3hXWjI5c2VUUlJJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsRWNWSnlXVTVmVjNKVGFrRlFkbmxGWWxKUVJWazRXVmhQUm1OdlQwUlRaRXhVVFdJdE0yRktWRWxHUVNJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUVV3eU1GZFlha3BRUVc1NFdXZFFZMVU1UlY5UE9FMU9kSE5wUWswMFFrdHBhVk53VDNaRlRXcFZPVUVpZlgwIiwidnAiOnsiQGNvbnRleHQiOlsiaHR0cHM6XC9cL3d3dy53My5vcmdcLzIwMThcL2NyZWRlbnRpYWxzXC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iXSwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOlsiZXlKcmFXUWlPaUprYVdRNmFXOXVPa1ZwUWtGQk9UbFVRV1Y2ZUV0U1l6SjNkWFZDYm5JMGVucEhjMU15V1dOelQwRTBTVkJSVmpCTFdUWTBXR2M2WlhsS2ExcFhlREJaVTBrMlpYbEtkMWxZVW1waFIxWjZTV3B3WW1WNVNtaFpNMUp3WWpJMGFVOXBTbmxhV0VKeldWZE9iRWxwZDJsYVJ6bHFaRmN4YkdKdVVXbFBibk5wWTBoV2FXSkhiR3BUTWxZMVkzbEpObGN6YzJsaFYxRnBUMmxLY2xwWWEzUk5VMGx6U1c1Q01WbHRlSEJaTUhSc1pWVndNMkY1U1RabGVVcHFZMjVaYVU5cFNrWmFSRWt4VGxSRk5VbHBkMmxoTTFJMVNXcHZhVlF3ZEZGSmFYZHBaVU5KTmtsclpHNVhhMlJWV25wb2JGRXlSVE5pUmxsNVQwVXhUVTlWY0ZWaVZVcFdaRzF6TTFKR2JFTlpiVnBUVXpGa1RXRklZekpPVlhCMlRWaE5hVXhEU25KaFYxRnBUMmxLY2xwWWEzUk5VMG81VEVOS2QyUllTbmRpTTA1c1kzbEpObGQ1U21oa1dGSnZXbGMxTUdGWFRtaGtSMngyWW1sS1pFeERTakJsV0VKc1NXcHZhVk51VG5aaWJHUnNXV3QwYkdWVVNYZE5ha0ZwWmxZeE9XWldNSE5KYmxaM1drZEdNRnBWVG5aaVZ6RndaRWN4YkdKdVVXbFBhVXBHWVZWU1MxWXdXakpYVlVvMVVYcGtNbUY2UVRKTldFRjZaRWhaZDJReU9WZFRWR3MxVFZSR1VWUkhaM2RWVm5BMFkxZHdXazB5V1RSTlZrWlNTVzR3YzBsdVRqRmFiVnB3WlVWU2FHUkhSV2xQYm5OcFdrZFdjMlJIUmtsWldFNXZTV3B2YVZKWGJFSllNVkoyVm14T1FscEVRbFJTVjNoUFZUSldjbEV4YXpGVlJGWklXakF4UzFGNU1VMVVWbkJHV1RKYVUxWXlXbkZhUjA1aFdWaEtSbEZUU1hOSmJrcHNXVEk1TWxwWVNqVlJNamwwWWxkc01HSlhWblZrUTBrMlNXdFdjRkpFVGpCYVZGWTBaVVpzYVdWdFNtOWtNSEJaWkVWVmQxb3lkRnBXTTFvelRXeGFNbFpHUWpSTlZUbHNZVEJTVkdOWVpIVmFlbEpVVjIxamFXWllNQ05yWlhrdE1TSXNJblI1Y0NJNklrcFhWQ0lzSW1Gc1p5STZJa1ZrUkZOQkluMC5leUp6ZFdJaU9pSmthV1E2YVc5dU9rVnBRV1ZOTms1dk9XdGtjRzl6Tmw5bGFFSlZSR2cwVWtsT1dUUlZVMFJOYUMxUlpGZHJjMjF6U1ROWGEwRTZaWGxLYTFwWGVEQlpVMGsyWlhsS2QxbFlVbXBoUjFaNlNXcHdZbVY1U21oWk0xSndZakkwYVU5cFNubGFXRUp6V1ZkT2JFbHBkMmxhUnpscVpGY3hiR0p1VVdsUGJuTnBZMGhXYVdKSGJHcFRNbFkxWTNsSk5sY3pjMmxoVjFGcFQybEtjbHBZYTNSTlUwbHpTVzVDTVZsdGVIQlpNSFJzWlZWd00yRjVTVFpsZVVwcVkyNVphVTlwU2taYVJFa3hUbFJGTlVscGQybGhNMUkxU1dwdmFWUXdkRkZKYVhkcFpVTkpOa2x1WTNkT2F6bFhUakpWTW1Kc1VqRmpibEV5VW5wc1YyTkdXbGxsUld3elYxYzFOV0Z0V2pGalNHaHNVak5zVEZGc1RYUlpiWGg0WkcxamFVeERTbkpoVjFGcFQybEtjbHBZYTNSTlUwbzVURU5LZDJSWVNuZGlNMDVzWTNsSk5sZDVTbWhrV0ZKdldsYzFNR0ZYVG1oa1IyeDJZbWxLWkV4RFNqQmxXRUpzU1dwdmFWTnVUblppYkdSc1dXdDBiR1ZVU1hkTmFrRnBabFl4T1daV01ITkpibFozV2tkR01GcFZUblppVnpGd1pFY3hiR0p1VVdsUGFVcEdZVlZHVTA1SFVsWlJiWGh4VGxkT1IyRXpaRTFrYTNCVVYxVlplbFpGZUdwTVZqZ3hUVmRvUkZneWVGcGhSM2hZV210NFYxb3lPWE5sVkZKU1NXNHdjMGx1VGpGYWJWcHdaVVZTYUdSSFJXbFBibk5wV2tkV2MyUkhSa2xaV0U1dlNXcHZhVkpYYkVWalZrcDVWMVUxWmxZelNsUmhhMFpSWkc1c1JsbHNTbEZTVm1zMFYxWm9VRkp0VG5aVU1GSlVXa1Y0VlZSWFNYUk5Na1pMVmtWc1IxRlRTWE5KYmtwc1dUSTVNbHBZU2pWUk1qbDBZbGRzTUdKWFZuVmtRMGsyU1d0V2NGRlZkM2xOUm1SWllXdHdVVkZYTlRSWFYyUlJXVEZWTlZKV09WQlBSVEZQWkVoT2NGRnJNREJSYTNSd1lWWk9kMVF6V2taVVYzQldUMVZGYVdaWU1DSXNJbTVpWmlJNk1UWTNORGMzTWpBMk15d2lhWE56SWpvaVpHbGtPbWx2YmpwRmFVSkJRVGs1VkVGbGVuaExVbU15ZDNWMVFtNXlOSHA2UjNOVE1sbGpjMDlCTkVsUVVWWXdTMWsyTkZobk9tVjVTbXRhVjNnd1dWTkpObVY1U25kWldGSnFZVWRXZWtscWNHSmxlVXBvV1ROU2NHSXlOR2xQYVVwNVdsaENjMWxYVG14SmFYZHBXa2M1YW1SWE1XeGlibEZwVDI1emFXTklWbWxpUjJ4cVV6SldOV041U1RaWE0zTnBZVmRSYVU5cFNuSmFXR3QwVFZOSmMwbHVRakZaYlhod1dUQjBiR1ZWY0ROaGVVazJaWGxLYW1OdVdXbFBhVXBHV2tSSk1VNVVSVFZKYVhkcFlUTlNOVWxxYjJsVU1IUlJTV2wzYVdWRFNUWkphMlJ1VjJ0a1ZWcDZhR3hSTWtVellrWlplVTlGTVUxUFZYQlZZbFZLVm1SdGN6TlNSbXhEV1cxYVUxTXhaRTFoU0dNeVRsVndkazFZVFdsTVEwcHlZVmRSYVU5cFNuSmFXR3QwVFZOS09VeERTbmRrV0VwM1lqTk9iR041U1RaWGVVcG9aRmhTYjFwWE5UQmhWMDVvWkVkc2RtSnBTbVJNUTBvd1pWaENiRWxxYjJsVGJrNTJZbXhrYkZscmRHeGxWRWwzVFdwQmFXWldNVGxtVmpCelNXNVdkMXBIUmpCYVZVNTJZbGN4Y0dSSE1XeGlibEZwVDJsS1JtRlZVa3RXTUZveVYxVktOVkY2WkRKaGVrRXlUVmhCZW1SSVdYZGtNamxYVTFSck5VMVVSbEZVUjJkM1ZWWndOR05YY0ZwTk1sazBUVlpHVWtsdU1ITkpiazR4V20xYWNHVkZVbWhrUjBWcFQyNXphVnBIVm5Oa1IwWkpXVmhPYjBscWIybFNWMnhDV0RGU2RsWnNUa0phUkVKVVVsZDRUMVV5Vm5KUk1Xc3hWVVJXU0Zvd01VdFJlVEZOVkZad1Jsa3lXbE5XTWxweFdrZE9ZVmxZU2taUlUwbHpTVzVLYkZreU9USmFXRW8xVVRJNWRHSlhiREJpVjFaMVpFTkpOa2xyVm5CU1JFNHdXbFJXTkdWR2JHbGxiVXB2WkRCd1dXUkZWWGRhTW5SYVZqTmFNMDFzV2pKV1JrSTBUVlU1YkdFd1VsUmpXR1IxV25wU1ZGZHRZMmxtV0RBaUxDSnBZWFFpT2pFMk56UTNOekl3TmpNc0luWmpJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2x3dlhDOTNkM2N1ZHpNdWIzSm5YQzh5TURFNFhDOWpjbVZrWlc1MGFXRnNjMXd2ZGpFaVhTd2lkSGx3WlNJNld5SldaWEpwWm1saFlteGxRM0psWkdWdWRHbGhiQ0lzSWxabGNtbG1hV1ZrUlcxd2JHOTVaV1VpWFN3aVkzSmxaR1Z1ZEdsaGJGTjFZbXBsWTNRaU9uc2laR2x6Y0d4aGVVNWhiV1VpT2lKUVlYUWdVMjFwZEdnaUxDSm5hWFpsYms1aGJXVWlPaUpRWVhRaUxDSnFiMkpVYVhSc1pTSTZJbGR2Y210bGNpSXNJbk4xY201aGJXVWlPaUpUYldsMGFDSXNJbkJ5WldabGNuSmxaRXhoYm1kMVlXZGxJam9pWlc0dFZWTWlMQ0p0WVdsc0lqb2ljR0YwTG5OdGFYUm9RR1Y0WVcxd2JHVXVZMjl0SW4wc0ltTnlaV1JsYm5ScFlXeFRkR0YwZFhNaU9uc2lhV1FpT2lKb2RIUndjenBjTDF3dlpYaGhiWEJzWlM1amIyMWNMMkZ3YVZ3dllYTjBZWFIxYzJ4cGMzUmNMMlJwWkRwcGIyNDZSV2xDUVVFNU9WUkJaWHA0UzFKak1uZDFkVUp1Y2pSNmVrZHpVekpaWTNOUFFUUkpVRkZXTUV0Wk5qUllaMXd2TVNNd0lpd2lkSGx3WlNJNklsSmxkbTlqWVhScGIyNU1hWE4wTWpBeU1WTjBZWFIxY3lJc0luTjBZWFIxYzB4cGMzUkpibVJsZUNJNklqQWlMQ0p6ZEdGMGRYTk1hWE4wUTNKbFpHVnVkR2xoYkNJNkltaDBkSEJ6T2x3dlhDOWxlR0Z0Y0d4bExtTnZiVnd2WVhCcFhDOWhjM1JoZEhWemJHbHpkRnd2Wkdsa09tbHZianBGYVVKQlFUazVWRUZsZW5oTFVtTXlkM1YxUW01eU5IcDZSM05UTWxsamMwOUJORWxRVVZZd1MxazJORmhuWEM4eEluMTlMQ0pxZEdraU9pSmlPREExTW1ZNVl5MDBaamhqTFRRek16QXRZbUpqTVMwME1ETXpZamhsWlRWa05tSWlmUS5WRWlLQ3IzUlZTY1VNRjgxRnhnckdDbGRZeEtJSmM0dWNMWDN6MHhha21sX0dPeG5udndrbzNDNlFxajdKTVVJOUs3dlFVVU1Wakk4MUt4a3RZdDBBUSJdfSwiZXhwIjoxNjc0Nzg2NDYzLCJpYXQiOjE2NzQ3NzIwNjMsIm5vbmNlIjoiNDAyNTJhZmMtNmE4Mi00YTJlLTkwNWYtZTQxZjEyMmVmNTc1IiwianRpIjoiOWNlZGFjODYtYWU1MS00MWQwLWFlNmYtOTI5NjZhNjFlMWY1In0.X9q1amromvW0WuA7bkanc-8BC9axhXh8RhN9i87FluTBzK3SRtKBS0O0alHU3Ii5HixENljCnncTKxi5_rbvDg',
  }

  public static jwtVCFromVPToken =
    'eyJraWQiOiJkaWQ6aW9uOkVpQkFBOTlUQWV6eEtSYzJ3dXVCbnI0enpHc1MyWWNzT0E0SVBRVjBLWTY0WGc6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklrZG5Xa2RVWnpobFEyRTNiRll5T0UxTU9VcFViVUpWZG1zM1JGbENZbVpTUzFkTWFIYzJOVXB2TVhNaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVSS1YwWjJXVUo1UXpkMmF6QTJNWEF6ZEhZd2QyOVdTVGs1TVRGUVRHZ3dVVnA0Y1dwWk0yWTRNVkZSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEJYMVJ2VmxOQlpEQlRSV3hPVTJWclExazFVRFZIWjAxS1F5MU1UVnBGWTJaU1YyWnFaR05hWVhKRlFTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFJETjBaVFY0ZUZsaWVtSm9kMHBZZEVVd1oydFpWM1ozTWxaMlZGQjRNVTlsYTBSVGNYZHVaelJUV21jaWZYMCNrZXktMSIsInR5cCI6IkpXVCIsImFsZyI6IkVkRFNBIn0.eyJzdWIiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCIsIm5iZiI6MTY3NDc3MjA2MywiaXNzIjoiZGlkOmlvbjpFaUJBQTk5VEFlenhLUmMyd3V1Qm5yNHp6R3NTMlljc09BNElQUVYwS1k2NFhnOmV5SmtaV3gwWVNJNmV5SndZWFJqYUdWeklqcGJleUpoWTNScGIyNGlPaUp5WlhCc1lXTmxJaXdpWkc5amRXMWxiblFpT25zaWNIVmliR2xqUzJWNWN5STZXM3NpYVdRaU9pSnJaWGt0TVNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUpGWkRJMU5URTVJaXdpYTNSNUlqb2lUMHRRSWl3aWVDSTZJa2RuV2tkVVp6aGxRMkUzYkZZeU9FMU1PVXBVYlVKVmRtczNSRmxDWW1aU1MxZE1hSGMyTlVwdk1YTWlMQ0pyYVdRaU9pSnJaWGt0TVNKOUxDSndkWEp3YjNObGN5STZXeUpoZFhSb1pXNTBhV05oZEdsdmJpSmRMQ0owZVhCbElqb2lTbk52YmxkbFlrdGxlVEl3TWpBaWZWMTlmVjBzSW5Wd1pHRjBaVU52YlcxcGRHMWxiblFpT2lKRmFVUktWMFoyV1VKNVF6ZDJhekEyTVhBemRIWXdkMjlXU1RrNU1URlFUR2d3VVZwNGNXcFpNMlk0TVZGUkluMHNJbk4xWm1acGVFUmhkR0VpT25zaVpHVnNkR0ZJWVhOb0lqb2lSV2xCWDFSdlZsTkJaREJUUld4T1UyVnJRMWsxVURWSFowMUtReTFNVFZwRlkyWlNWMlpxWkdOYVlYSkZRU0lzSW5KbFkyOTJaWEo1UTI5dGJXbDBiV1Z1ZENJNklrVnBSRE4wWlRWNGVGbGllbUpvZDBwWWRFVXdaMnRaVjNaM01sWjJWRkI0TVU5bGEwUlRjWGR1WnpSVFdtY2lmWDAiLCJpYXQiOjE2NzQ3NzIwNjMsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWVkRW1wbG95ZWUiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZGlzcGxheU5hbWUiOiJQYXQgU21pdGgiLCJnaXZlbk5hbWUiOiJQYXQiLCJqb2JUaXRsZSI6IldvcmtlciIsInN1cm5hbWUiOiJTbWl0aCIsInByZWZlcnJlZExhbmd1YWdlIjoiZW4tVVMiLCJtYWlsIjoicGF0LnNtaXRoQGV4YW1wbGUuY29tIn0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL2FwaVwvYXN0YXR1c2xpc3RcL2RpZDppb246RWlCQUE5OVRBZXp4S1JjMnd1dUJucjR6ekdzUzJZY3NPQTRJUFFWMEtZNjRYZ1wvMSMwIiwidHlwZSI6IlJldm9jYXRpb25MaXN0MjAyMVN0YXR1cyIsInN0YXR1c0xpc3RJbmRleCI6IjAiLCJzdGF0dXNMaXN0Q3JlZGVudGlhbCI6Imh0dHBzOlwvXC9leGFtcGxlLmNvbVwvYXBpXC9hc3RhdHVzbGlzdFwvZGlkOmlvbjpFaUJBQTk5VEFlenhLUmMyd3V1Qm5yNHp6R3NTMlljc09BNElQUVYwS1k2NFhnXC8xIn19LCJqdGkiOiJiODA1MmY5Yy00ZjhjLTQzMzAtYmJjMS00MDMzYjhlZTVkNmIifQ.VEiKCr3RVScUMF81FxgrGCldYxKIJc4ucLX3z0xakml_GOxnnvwko3C6Qqj7JMUI9K7vQUUMVjI81KxktYt0AQ'

  public static didDocument(did: string, vm: string, publicKeyJwk: JsonWebKey) {
    return {
      id: did,
      '@context': [
        'https://www.w3.org/ns/did/v1',
        {
          '@base': did,
        },
      ],
      service: [
        {
          id: '#linkedin',
          type: 'linkedin',
          serviceEndpoint: 'linkedin.com/in/henry-tsai-6b884014',
        },
        {
          id: '#github',
          type: 'github',
          serviceEndpoint: 'github.com/thehenrytsai',
        },
      ],
      verificationMethod: [
        {
          id: vm,
          controller: did,
          type: 'JsonWebKey2020',
          publicKeyJwk,
        },
      ],
      authentication: [vm],
      assertionMethod: [vm],
    }
  }

  public static mockDID(did: string, vm: string, publickKeyJwk: JsonWebKey) {
    nock('https://dev.uniresolver.io')
      .get(`/1.0/identifiers/${did}`)
      .times(100)
      .reply(200, TestVectors.didDocument(did, vm, publickKeyJwk))
  }
}
