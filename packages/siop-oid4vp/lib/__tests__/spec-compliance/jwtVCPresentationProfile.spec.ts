import { SigningAlgo } from '@sphereon/oid4vc-common'
import { PresentationSignCallBackParams } from '@sphereon/pex'
import * as jose from 'jose'
import { KeyLike } from 'jose'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as u8a from 'uint8arrays'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { getVerifyJwtCallback, internalSignature } from '../DidJwtTestUtils'
import { getResolver } from '../ResolverTestUtils'
import {
  AuthorizationRequest,
  AuthorizationResponse,
  IDToken,
  OP,
  PassBy,
  PresentationSignCallback,
  PresentationVerificationCallback,
  PropertyTarget,
  ResponseMode,
  ResponseType,
  RevocationVerification,
  RP,
  SupportedVersion
} from '../..'
import {DcqlPresentation, DcqlQuery, DcqlQueryResult, DcqlSdJwtVcCredential} from 'dcql';

const { fromString, toString } = u8a

let rp: RP
let op: OP

afterEach(() => {
  nock.cleanAll()
})

const presentationVerificationCallback: PresentationVerificationCallback = async () => ({ verified: true })
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const presentationSignCallback: PresentationSignCallback = async (_args: PresentationSignCallBackParams) =>
  TestVectors.authorizationResponsePayload.vp_token

const verifyJwtCallback = getVerifyJwtCallback(getResolver('jwk'), { // TODO ion
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
            alg: ['EdDSA', 'ES256K'],
          },
          jwt_vp: {
            alg: ['EdDSA', 'ES256K'],
          },
        },
        subject_syntax_types_supported: ['did:jwk'], //ion
      },
      PropertyTarget.REQUEST_OBJECT,
    )
    .withRedirectUri('https://example.com/siop-response', PropertyTarget.REQUEST_OBJECT)
    .withRequestBy(PassBy.REFERENCE, TestVectors.request_uri)
    .withCreateJwtCallback(internalSignature(TestVectors.verifierHexPrivateKey, TestVectors.verifierDID, TestVectors.verifierKID, SigningAlgo.EDDSA))
    .withVerifyJwtCallback(verifyJwtCallback)
    .build()

  op = OP.builder()
    .withCreateJwtCallback(internalSignature(TestVectors.holderHexPrivateKey, TestVectors.holderDID, TestVectors.holderKID, SigningAlgo.ES256)) //EDDSA
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
      client_id:
        'did:ion:EiBAA99TAezxKRc2wuuBnr4zzGsS2YcsOA4IPQV0KY64Xg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkdnWkdUZzhlQ2E3bFYyOE1MOUpUbUJVdms3RFlCYmZSS1dMaHc2NUpvMXMiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaURKV0Z2WUJ5Qzd2azA2MXAzdHYwd29WSTk5MTFQTGgwUVp4cWpZM2Y4MVFRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBX1RvVlNBZDBTRWxOU2VrQ1k1UDVHZ01KQy1MTVpFY2ZSV2ZqZGNaYXJFQSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpRDN0ZTV4eFliemJod0pYdEUwZ2tZV3Z3MlZ2VFB4MU9la0RTcXduZzRTWmcifX0',
      response_mode: 'post',
      scope: 'openid',
      claims: {
        vp_token: {
          dcql_query: JSON.stringify(TestVectors.parsedDcqlQuery)
        },
      },
      registration: {
        logo_uri: 'https://example.com/verifier-icon.png',
        tos_uri: 'https://example.com/verifier-info',
        client_name: 'Example Verifier',
        vp_formats: {
          jwt_vc: {
            alg: ['EdDSA', 'ES256K'],
          },
          jwt_vp: {
            alg: ['EdDSA', 'ES256K'],
          },
        },
        subject_syntax_types_supported: ['did:ion'],
      },
      state: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
      redirect_uri: 'https://example.com/siop-response' /*,
        "exp" : 1674775663,
        "iat" : 1674772063,
        "jti" : "f0e6dcf5-3fe6-4507-adc9-b496daf34512"*/,
    })
  })

  it('should re-create uri', async () => {
    const authRequest = await createAuthRequest()
    const uri = await authRequest.uri()
    expect(uri.encodedUri).toEqual(
      'openid-vc://?request_uri=https%3A%2F%2Fexample%2Fservice%2Fapi%2Fv1%2Fpresentation-request%2F649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9&client_id=decentralized_identifier%3Adid%3Aion%3AEiBAA99TAezxKRc2wuuBnr4zzGsS2YcsOA4IPQV0KY64Xg%3AeyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkdnWkdUZzhlQ2E3bFYyOE1MOUpUbUJVdms3RFlCYmZSS1dMaHc2NUpvMXMiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaURKV0Z2WUJ5Qzd2azA2MXAzdHYwd29WSTk5MTFQTGgwUVp4cWpZM2Y4MVFRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBX1RvVlNBZDBTRWxOU2VrQ1k1UDVHZ01KQy1MTVpFY2ZSV2ZqZGNaYXJFQSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpRDN0ZTV4eFliemJod0pYdEUwZ2tZV3Z3MlZ2VFB4MU9la0RTcXduZzRTWmcifX0',
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
        audience: "did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiaTlBdmpJMFdjUXo5NF9aVkVDazVrS21kSEFEU2RWNGRKZ1RNN0ROYkNJayIsInkiOiJJZGtyWktUcWdmNE1ZY3hUbHlIM3ZJMkdHYjJXYWM1Z0V1Y0lQaTFfRmtnIn0",//'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0',
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
        audience:
          'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0',
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
        audience:
          'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0',
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
    // expect.assertions(1);
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
      aud: 'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0',
      exp: 1674786463,
      iat: 1674772063,
      iss: 'https://self-issued.me/v2/openid-vc',
      jti: '0f5dafed-0d82-43b1-af79-40440e3f1366',
      nonce: '40252afc-6a82-4a2e-905f-e41f122ef575',
      sub: 'did:ion:EiAeM6No9kdpos6_ehBUDh4RINY4USDMh-QdWksmsI3WkA:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IncwNk9WN2U2blR1cnQ2RzlWcFZYeEl3WW55amZ1cHhlR3lLQlMtYmxxdmciLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUFSNGRVQmxqNWNGa3dMdkpTWUYzVExjLV81MWhDX2xZaGxXZkxWZ29seTRRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlEcVJyWU5fV3JTakFQdnlFYlJQRVk4WVhPRmNvT0RTZExUTWItM2FKVElGQSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQUwyMFdYakpQQW54WWdQY1U5RV9POE1OdHNpQk00QktpaVNwT3ZFTWpVOUEifX0',
    })

    await rp.verifyAuthorizationResponse(TestVectors.authorizationResponsePayload, {
      audience:
        'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0',
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

    // TODO cleanup and make proper test, see where we need to get this sdjwt and dcql presentation
    const sdjwt = {
      compactJwtVc:
          'eyJ0eXAiOiJ2YytzZC1qd3QiLCJraWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lTMGRwYzNodlUzaDJhVzB4YTFOSU1XSnROMnhmUkhCeVIyczNZa2RrWkVaYVdXWnRjVXB1VjJWb1NTSXNJbmtpT2lKYVEzQldUVVZSTkhsNGNUSlZiVGRDVGpoSVQyNUdlamszTTFBMFVUQlVkbmRuZVhWUlgyRmlURlZWSW4wIzAiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lXRkpXUVhsNVJIQldNbXBNTm5oNlUwSktZM1JIZW0xS1pqbFFlV0Z4WHpNdFRVeHJlR0ZoUlRBNFRTSXNJbmtpT2lKQ1NtOUtWM05WYTBaQlUyVlRZMmx4VDFsNVNWTTBZMFpoZVU4emFHaEJTalZaYjJ0dU9IcFRTVEZuSW4wIzAiLCJpc3MiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lTMGRwYzNodlUzaDJhVzB4YTFOSU1XSnROMnhmUkhCeVIyczNZa2RrWkVaYVdXWnRjVXB1VjJWb1NTSXNJbmtpT2lKYVEzQldUVVZSTkhsNGNUSlZiVGRDVGpoSVQyNUdlamszTTFBMFVUQlVkbmRuZVhWUlgyRmlURlZWSW4wIzAiLCJpYXQiOjE3MzQ0NTgwNDIsInZjdCI6InVybjpldS5ldXJvcGEuZWMuZXVkaTpwaWQ6MSIsIl9zZCI6WyIwWWdpR25hck1LSERnVWx1QktteGdRZUJ4OF8xazMwd3NSRVN1X2t1Y0JFIiwiNEpwU2JzUEsxZndUQzRhR24zZ0hXb1BkVEJrMExOTWZMOEJXeEIxZ1JPWSIsIjRpZmplQUZveUEyQmc0STVNWEFrMVlyc1AtUVBQQXRnZGlHY0RMQTZiTFEiLCJBdTFjdURISUNISE1jUjZxM2R3d1pHbHp5dzMwSXhvTGVhWlNxRktEbmo4IiwiQ0QxbWxOY19VaVBoQUp6YkJveTVMY3dtekFNZTM3d0VLZF9iMTB6QTNxNCIsInFwZ1FOUVRac0VJWHdxUk9fT24xdUVCSVVNODBTcTJLR2tlN0JSU2N0WHciXSwiX3NkX2FsZyI6IlNIQS0yNTYifQ.P84d0CoS4M-zQ29l3S97RMatfJMYkoTgR5EqSMTdYlZAMp4e8iiuz2PXQMfJ-_undCvg4SRXxDACGiLL3Tt7Bw~WyJlNTFiNWI2NS0wNzM3LTQ0MjQtYTUxYS1jNGYzZGNlZGFmMmYiLCJnaXZlbl9uYW1lIiwiSm9obiJd~WyIxM2I1NDIwNi1kYWQ3LTQ3N2UtODYyZC03N2ZiMTQ1MDE5NjUiLCJmYW1pbHlfbmFtZSIsIkRvZSJd~WyJkMmQxNjg3Zi04ZmY4LTRlOTMtYWJjYi1hYTNlNGVjYzY0ZTMiLCJlbWFpbCIsImpvaG5kZW9AZXhhbXBsZS5jb20iXQ~WyIyZDA4YTk2YS03YzYwLTQ3NDEtYTI5YS00ZjBjYTFlNGQ3M2IiLCJwaG9uZSIsIisxLTIwMi01NTUtMDEwMSJd~WyI2YjVkN2FmOS01ZmIxLTQzNTEtYWM1ZS1hMzA1YTBkNjU0ZDUiLCJhZGRyZXNzIix7InN0cmVldF9hZGRyZXNzIjoiMTIzIE1haW4gU3QiLCJsb2NhbGl0eSI6IkFueXRvd24iLCJyZWdpb24iOiJBbnlzdGF0ZSIsImNvdW50cnkiOiJVUyJ9XQ~WyI5MmYzY2M5ZC0yMjQ2LTRiODQtYTk5OS0xYmQyM2U0OGQ0MGEiLCJiaXJ0aGRhdGUiLCIxOTQwLTAxLTAxIl0~',
      decodedPayload: {
        header: {
          typ: 'vc+sd-jwt',
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
      credential_format: 'vc+sd-jwt',
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
    jwtIssuer: { method: 'did', alg: SigningAlgo.EDDSA, didUrl: TestVectors.verifierKID },
    claims: {
      propertyValue: {
        vp_token: {
          dcql_query: JSON.stringify(TestVectors.parsedDcqlQuery),
        },
      },
      targets: PropertyTarget.REQUEST_OBJECT,
    },
  })
}

class TestVectors {
  public static issuerDID =
    'did:ion:EiBAA99TAezxKRc2wuuBnr4zzGsS2YcsOA4IPQV0KY64Xg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkdnWkdUZzhlQ2E3bFYyOE1MOUpUbUJVdms3RFlCYmZSS1dMaHc2NUpvMXMiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaURKV0Z2WUJ5Qzd2azA2MXAzdHYwd29WSTk5MTFQTGgwUVp4cWpZM2Y4MVFRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBX1RvVlNBZDBTRWxOU2VrQ1k1UDVHZ01KQy1MTVpFY2ZSV2ZqZGNaYXJFQSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpRDN0ZTV4eFliemJod0pYdEUwZ2tZV3Z3MlZ2VFB4MU9la0RTcXduZzRTWmcifX0'
  public static issuerKID = `${TestVectors.issuerDID}#key-1`
  public static issuerJwk = {
    kty: 'OKP',
    d: 'jGLXxgOFN5DuQQFrRBN58Xll5SRizDXyVL5uiDY60_4',
    crv: 'Ed25519',
    kid: 'key-1',
    x: 'GgZGTg8eCa7lV28ML9JTmBUvk7DYBbfRKWLhw65Jo1s',
  }
  public static issuerKey: KeyLike
  public static issuerPrivateKey: string
  public static issuerPublicKey: string
  public static issuerHexPrivateKey: string

  public static holderJwk = {
    kty: 'OKP',
    d: 'ZeDOVmemqzPAK0R2F1BHVfRYC7g65p_UpyXhEaX03N4',
    crv: 'Ed25519',
    kid: 'key-1',
    x: 'w06OV7e6nTurt6G9VpVXxIwYnyjfupxeGyKBS-blqvg',
  }
  public static holderDID =
    //'did:ion:EiAeM6No9kdpos6_ehBUDh4RINY4USDMh-QdWksmsI3WkA:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IncwNk9WN2U2blR1cnQ2RzlWcFZYeEl3WW55amZ1cHhlR3lLQlMtYmxxdmciLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUFSNGRVQmxqNWNGa3dMdkpTWUYzVExjLV81MWhDX2xZaGxXZkxWZ29seTRRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlEcVJyWU5fV3JTakFQdnlFYlJQRVk4WVhPRmNvT0RTZExUTWItM2FKVElGQSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQUwyMFdYakpQQW54WWdQY1U5RV9POE1OdHNpQk00QktpaVNwT3ZFTWpVOUEifX0'
    'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiaTlBdmpJMFdjUXo5NF9aVkVDazVrS21kSEFEU2RWNGRKZ1RNN0ROYkNJayIsInkiOiJJZGtyWktUcWdmNE1ZY3hUbHlIM3ZJMkdHYjJXYWM1Z0V1Y0lQaTFfRmtnIn0'
  public static holderKID = `${TestVectors.holderDID}#key-1`
  public static holderKey: KeyLike
  public static holderPrivateKey: string
  public static holderPublicKey: string
  public static holderHexPrivateKey: string

  public static verifierJwk = {
    kty: 'OKP',
    d: 'SP18SnbU9f-Rph0GwulyvmLFyCXDHqZVKWDo2E41llQ',
    crv: 'Ed25519',
    kid: 'key-1',
    x: 'C_OUJxH6iIcC6XdNh7JmC-THXAVaXnvu9OEEZ8tq9NI',
  }
  public static verifierDID =
    //'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0'
  'did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiaTlBdmpJMFdjUXo5NF9aVkVDazVrS21kSEFEU2RWNGRKZ1RNN0ROYkNJayIsInkiOiJJZGtyWktUcWdmNE1ZY3hUbHlIM3ZJMkdHYjJXYWM1Z0V1Y0lQaTFfRmtnIn0'

  public static verifierKID = `${TestVectors.verifierDID}#key-1`
  public static verifierKey: jose.KeyLike | Uint8Array
  public static verifierPrivateKey: string
  public static verifierPublicKey: string
  public static verifierHexPrivateKey: string

  public static async init() {
    TestVectors.issuerKey = (await jose.importJWK(TestVectors.issuerJwk, 'EdDSA', true)) as KeyLike
    TestVectors.issuerPrivateKey = toString(fromString(TestVectors.issuerJwk.d, 'base64url'), 'hex')
    TestVectors.issuerPublicKey = toString(fromString(TestVectors.issuerJwk.x, 'base64url'), 'hex')
    TestVectors.issuerHexPrivateKey = `${TestVectors.issuerPrivateKey}${TestVectors.issuerPublicKey}`

    TestVectors.holderKey = (await jose.importJWK(TestVectors.holderJwk, 'EdDSA', true)) as KeyLike
    TestVectors.holderPrivateKey = toString(fromString(TestVectors.holderJwk.d, 'base64url'), 'hex')
    TestVectors.holderPublicKey = toString(fromString(TestVectors.holderJwk.x, 'base64url'), 'hex')
    TestVectors.holderHexPrivateKey = `${TestVectors.holderPrivateKey}${TestVectors.holderPublicKey}`

    TestVectors.verifierKey = (await jose.importJWK(TestVectors.verifierJwk, 'EdDSA', true)) as KeyLike
    TestVectors.verifierPrivateKey = toString(fromString(TestVectors.verifierJwk.d, 'base64url'), 'hex')
    TestVectors.verifierPublicKey = toString(fromString(TestVectors.verifierJwk.x, 'base64url'), 'hex')
    TestVectors.verifierHexPrivateKey = `${TestVectors.verifierPrivateKey}${TestVectors.verifierPublicKey}`
  }

  public static auth_request = 'openid-vc://?request_uri=https://example/service/api/v1/presentation-request/649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9'
  public static request_uri = 'https://example/service/api/v1/presentation-request/649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9'

  // public static idTokenJwt =
  //   'eyJraWQiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJzdWIiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCIsImF1ZCI6ImRpZDppb246RWlCV2U5UnRIVDdWWi1KdWZmOE9ubkpBeUZKdENva2NZSHgxQ1FrRnRwbDdwdzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtOZlQxVktlRWcyYVVsalF6WllaRTVvTjBwdFF5MVVTRmhCVm1GWWJuWjFPVTlGUlZvNGRIRTVUa2tpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5ZVGtKcVNXWk1WR1pPVjBOSE1GUTJNMlZhWW1KRVpGWm9TbUpVVGpndFNtWmxhVXg0ZFcxb1pXNTNJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQ1pWWjVSWEJEYjBOUGVYSjZWRGhEU0hsdlFXMWFjVTFDVDFvMFZUWnFjbTFzZFV0MVNqbHhTMHBrWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUW5oa2NIbHlhbWxWU0ZaMWFrTlJXVEJLTWtoQlVGRllabk53V0ZCS1lXbHVWMjFtVjNSTmNGaG5lRkVpZlgwIiwiaXNzIjoiaHR0cHM6XC9cL3NlbGYtaXNzdWVkLm1lXC92Mlwvb3BlbmlkLXZjIiwiZXhwIjoxNjc0Nzg2NDYzLCJpYXQiOjE2NzQ3NzIwNjMsIm5vbmNlIjoiNDAyNTJhZmMtNmE4Mi00YTJlLTkwNWYtZTQxZjEyMmVmNTc1IiwianRpIjoiMGY1ZGFmZWQtMGQ4Mi00M2IxLWFmNzktNDA0NDBlM2YxMzY2IiwiX3ZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoiOWFmMjRlOGEtYzhmMy00YjlhLTkxNjEtYjcxNWU3N2E2MDEwIiwiZGVmaW5pdGlvbl9pZCI6IjY0OWQ4YzNjLWY1YWMtNDFiZC05YzE5LTU4MDRlYTFiOGZlOSIsImRlc2NyaXB0b3JfbWFwIjpbeyJpZCI6IlZlcmlmaWVkRW1wbG95ZWVWQyIsImZvcm1hdCI6Imp3dF92cCIsInBhdGgiOiIkIiwicGF0aF9uZXN0ZWQiOnsiaWQiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJmb3JtYXQiOiJqd3RfdmMiLCJwYXRoIjoiJC52ZXJpZmlhYmxlQ3JlZGVudGlhbFswXSJ9fV19fX0.jh-SnpQcYPGEb_N5mqKUKCi9pA2OqxXw7BbAYuQwQat69KqpHA0sEZ1tOTOwsVP9UCfjmVg_8z0I_TvKkEkCBA'

  public static idTokenJwt =
//'eyJhbGciOiJSUzI1NiIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMWVzZmh3aVJTcEZZRzNsRnN2WWdsamhadFNlYnpaMnpnd3pHckJ6NDZmSnV6NDlzd2FuWkZMQ1otdG5FeERZQUNORy1sUWY0azdhc01xWFdGRU1VMm94SVoxSnZfUlhrSF9MNF9BdC1EaVBQTkQzb1lIcjRna0t3cFZxeTg0dzNIQkw2RUZVaXJjX0FOV00zTjBxcnNQTGtIeFNsYWp3Z3lzdXAxWTRVM2d4NF9iY1FTVTM2SmhfbG1CNlE5N0xwa1Y3dHhnZWNXVUJzQXVoOXQzSzJpYVZkVWNOd184LTV4WmFwWVBRRUdjRXA0N3lQaXhPSjJTbVhwb1IyaVRwdlpLNFpOeUYzSnhxS1FnMnBHSnFWYlZvdnRoU3dkeFFrT3FGMjFvYlFkNklpSmN2RG1uSFN4TG82RGlIQkdZRVl4Sk84M1BTa1RZM1h5aDd5Wk1Ba1V3IiwiZSI6IkFRQUIiLCJ4NWMiOlsiTUlJRkZqQ0NBdjZnQXdJQkFnSVJBSkVyQ0VyUERCaW5VL2JXTGlXblgxb3dEUVlKS29aSWh2Y05BUUVMQlFBd1R6RUxNQWtHQTFVRUJoTUNWVk14S1RBbkJnTlZCQW9USUVsdWRHVnlibVYwSUZObFkzVnlhWFI1SUZKbGMyVmhjbU5vSUVkeWIzVndNUlV3RXdZRFZRUURFd3hKVTFKSElGSnZiM1FnV0RFd0hoY05NakF3T1RBME1EQXdNREF3V2hjTk1qVXdPVEUxTVRZd01EQXdXakF5TVFzd0NRWURWUVFHRXdKVlV6RVdNQlFHQTFVRUNoTU5UR1YwSjNNZ1JXNWpjbmx3ZERFTE1Ba0dBMVVFQXhNQ1VqTXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDN0FoVW96UGFnbE5NUEV1eU5WWkxEK0lMeG1hWjZRb2luWFNhcXRTdTV4VXl4cjQ1citYWElvOWNQUjVRVVZUVlhqSjZvb2prWjlZSThRcWxPYnZVN3d5N2JqY0N3WFBOWk9PZnR6Mm53V2dzYnZzQ1VKQ1dIK2pkeHN4UG5IS3pobSsvYjVEdEZVa1dXcWNGVHpqVElVdTYxcnUyUDNtQnc0cVZVcTdadERwZWxRRFJySzlPOFp1dG1OSHo2YTR1UFZ5bVorREFYWGJweWIvdUJ4YTNTaGxnOUY4Zm5DYnZ4Sy9lRzNNSGFjVjNVUnVQTXJTWEJpTHhnWjNWbXMvRVk5NkpjNWxQL09vaTJSNlgvRXhqcW1BbDNQNTFUK2M4QjVmV21jQmNVcjJPay81bXprNTNjVTZjRy9raUZIYUZwcmlWMXV4UE1VZ1AxN1ZHaGk5c1ZBZ01CQUFHamdnRUlNSUlCQkRBT0JnTlZIUThCQWY4RUJBTUNBWVl3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdJR0NDc0dBUVVGQndNQk1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdIUVlEVlIwT0JCWUVGQlF1c3hlM1dGYkxybEFKUU9ZZnI1MkxGTUxHTUI4R0ExVWRJd1FZTUJhQUZIbTBXZVo3dHVYa0FYT0FDSWpJR2xqMjZadHVNRElHQ0NzR0FRVUZCd0VCQkNZd0pEQWlCZ2dyQmdFRkJRY3dBb1lXYUhSMGNEb3ZMM2d4TG1rdWJHVnVZM0l1YjNKbkx6QW5CZ05WSFI4RUlEQWVNQnlnR3FBWWhoWm9kSFJ3T2k4dmVERXVZeTVzWlc1amNpNXZjbWN2TUNJR0ExVWRJQVFiTUJrd0NBWUdaNEVNQVFJQk1BMEdDeXNHQVFRQmd0OFRBUUVCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFDRnlrNUhQcVAzaFVTRnZOVm5lTEtZWTYxMVRSNldQVE5sY2xRdGdhRHF3KzM0SUw5ZnpMZHdBTGR1Ty9aZWxON2tJSittNzR1eUErZWl0Ulk4a2M2MDdUa0M1M3dsaWtmbVpXNC9SdlRaOE02VUsrNVV6aEs4akNkTHVNR1lMNkt2elhHUlNnaTN5TGdqZXdRdENQa0lWejZEMlFRekNrY2hlQW1DSjhNcXlKdTV6bHp5Wk1qQXZubkFUNDV0UkF4ZWtyc3U5NHNRNGVnZFJDbmJXU0R0WTdraCtCSW1sSk5Yb0IxbEJNRUtJcTRRRFVPWG9SZ2ZmdURnaGplMVdyRzlNTCtIYmlzcS95Rk9Hd1hEOVJpWDhGNnN3Nlc0YXZBdXZEc3p1ZTVMM3N6ODVLK0VDNFkvd0ZWRE52Wm80VFlYYW82WjBmK2xRS2MwdDhEUVl6azFPWFZ1OHJwMnlKTUM2YWxMYkJmT0RBTFp2WUg3bjdkbzFBWmxzNEk5ZDFQNGpua0RyUW94QjNVcVE5aFZsM0xFS1E3M3hGMU95SzVHaEREWDhvVmZHS0Y1dStkZWNJc0g0WWFUdzdtUDNHRnhKU3F2MyswbFVGSm9pNUxjNWRhMTQ5cDkwSWRzaENFeHJvTDErN21yeUlrWFBlRk01VGdPOXIwcnZaYUJGT3ZWMnowZ3AzNVowK0w0V1BsYnVFak4vbHhQRmluK0hsVWpyOGdSc0kzcWZKT1FGeS85cktJSlIwWS84T213dC84b1RXZ3kxbWRlSG1tams3ajFuWXN2QzlKU1E2WnZNbGRsVFRLQjN6aFRoVjErWFdZcDZyamQ1SlcxemJWV0VrTE54RTdHSlRoRVVHM3N6Z0JWR1A3cFNXVFVUc3FYbkxSYndIT29xN2hId2c9PSIsIk1JSUZZRENDQkVpZ0F3SUJBZ0lRUUFGM0lUZlU2VUs0N25hcVBHUUt0ekFOQmdrcWhraUc5dzBCQVFzRkFEQS9NU1F3SWdZRFZRUUtFeHRFYVdkcGRHRnNJRk5wWjI1aGRIVnlaU0JVY25WemRDQkRieTR4RnpBVkJnTlZCQU1URGtSVFZDQlNiMjkwSUVOQklGZ3pNQjRYRFRJeE1ERXlNREU1TVRRd00xb1hEVEkwTURrek1ERTRNVFF3TTFvd1R6RUxNQWtHQTFVRUJoTUNWVk14S1RBbkJnTlZCQW9USUVsdWRHVnlibVYwSUZObFkzVnlhWFI1SUZKbGMyVmhjbU5vSUVkeWIzVndNUlV3RXdZRFZRUURFd3hKVTFKSElGSnZiM1FnV0RFd2dnSWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJS0FvSUNBUUN0NkNSejlCUTM4NXVlSzFjb0hJZSszTGZmT0pDTWJqem1WNkI0OTNYQ292NzFhbTcyQUU4bzI5NW9obXhFazdheFkvMFVFbXUvSDlMcU1ac2hmdEV6UExwSTlkMTUzN080L3hMeElacEx3WXFHY1dsS1ptWnNqMzQ4Y0wrdEtTSUc4K1RBNW9DdTRrdVB0NWwrbEFPZjAwZVhmSmxJSTFQb09LNVBDbStETHRGSlY0eUFkTGJhTDlBNGpYc0RjQ0ViZGZJd1BQcVBydDNhWTZ2ckZrL0NqaEZMZnM4TDZQKzFkeTcwc250SzRFd1NKUXh3alFNcG9PRlRKT3dUMmU0WnZ4Q3pTb3cvaWFOaFVkNnNod2VVOUdOeDdDN2liMXVZZ2VHSlhEUjViSGJ2TzVCaWVlYmJwSm92SnNYUUVPRU8zdGtRamhiN3QvZW85OGZsQWdlWWp6WUlsZWZpTjVZTk5uV2UrdzV5c1IyYnZBUDVTUVhZZ2QwRnRDcldRZW1zQVhhVkNnL1kzOVc5RWg4MUx5Z1hiTktZd2FnSlpIZHVSemU2enF4WlhtaWRmM0xXaWNVR1FTaytXVDdkSnZVa3lSR25XcU5NUUI5R29abTFwenBSYm9ZN25uMXlweElGZUZudFBsRjRGUXNEajQzUUx3V3lQbnRLSEV0ekJSTDh4dXJnVUJOOFE1TjBzOHAwNTQ0ZkFRalFNTlJiY1RhMEI3ckJNREJjU0xlQ081aW1mV0NLb3FNcGdzeTZ2WU1FRzZLREEwR2gxZ1h4RzhLMjhLaDhoanRHcUVncWlOeDJtbmEvSDJxbFBSbVA2emp6Wk43SUt3MEtLUC8zMitJVlF0UWkwQ2RkNFhuK0dPZHdpSzFPNXRtTE9zYmRKMUZ1Lzd4azlUTkRUd0lEQVFBQm80SUJSakNDQVVJd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBT0JnTlZIUThCQWY4RUJBTUNBUVl3U3dZSUt3WUJCUVVIQVFFRVB6QTlNRHNHQ0NzR0FRVUZCekFDaGk5b2RIUndPaTh2WVhCd2N5NXBaR1Z1ZEhKMWMzUXVZMjl0TDNKdmIzUnpMMlJ6ZEhKdmIzUmpZWGd6TG5BM1l6QWZCZ05WSFNNRUdEQVdnQlRFcDdHa2V5eHgrdHZoUzVCMS84UVZZSVdKRURCVUJnTlZIU0FFVFRCTE1BZ0dCbWVCREFFQ0FUQS9CZ3NyQmdFRUFZTGZFd0VCQVRBd01DNEdDQ3NHQVFVRkJ3SUJGaUpvZEhSd09pOHZZM0J6TG5KdmIzUXRlREV1YkdWMGMyVnVZM0o1Y0hRdWIzSm5NRHdHQTFVZEh3UTFNRE13TWFBdm9DMkdLMmgwZEhBNkx5OWpjbXd1YVdSbGJuUnlkWE4wTG1OdmJTOUVVMVJTVDA5VVEwRllNME5TVEM1amNtd3dIUVlEVlIwT0JCWUVGSG0wV2VaN3R1WGtBWE9BQ0lqSUdsajI2WnR1TUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFBS2N3QnNsbTcvRGxMUXJ0Mk01MW9HclMrbzQ0Ky95UW9ERlZEQzVXeEN1MitiOUxSUHdrU0lDSFhNNndlYkZHSnVlTjdzSjdvNVhQV2lvVzVXbEhBUVU3Rzc1Sy9Rb3NNckFkU1c5TVVnTlRQNTJHRTI0SEdOdExpMXFvSkZsY0R5cVNNbzU5YWh5MmNJMnFCRExLb2JreC9KM3ZXcmFWMFQ5VnVHV0NMS1RWWGtjR2R0d2xmRlJqbEJ6NHBZZzFodG1mNVg2RFlPOEE0anF2MklsOURqWEE2VVNiVzFGelhTTHI5T2hlOFk0SVdTNndZN2JDa2pDV0RjUlFKTUVoZzc2ZnNPM3R4RStGaVlydXE5UlVXaGlGMW15djRRNlcrQ3lCRkNEZnZwN09PR0FONmRFT000K3FSOXNkam9TWUtFQnBzcjZHdFBBUXc0ZHk3NTNlYzUiXSwia2lkIjoiNjBEX0lYSmF6cGRUTG9fSkhLdk5KMTFxMHFTNjIxbkJsZmlOV3Q3MHRMNCJ9fQ.eyJzdWJfandrIjoie1wia3R5XCI6XCJSU0FcIixcIm5cIjpcIjFlc2Zod2lSU3BGWUczbEZzdllnbGpoWnRTZWJ6WjJ6Z3d6R3JCejQ2Zkp1ejQ5c3dhblpGTENaLXRuRXhEWUFDTkctbFFmNGs3YXNNcVhXRkVNVTJveElaMUp2X1JYa0hfTDRfQXQtRGlQUE5EM29ZSHI0Z2tLd3BWcXk4NHczSEJMNkVGVWlyY19BTldNM04wcXJzUExrSHhTbGFqd2d5c3VwMVk0VTNneDRfYmNRU1UzNkpoX2xtQjZROTdMcGtWN3R4Z2VjV1VCc0F1aDl0M0syaWFWZFVjTndfOC01eFphcFlQUUVHY0VwNDd5UGl4T0oyU21YcG9SMmlUcHZaSzRaTnlGM0p4cUtRZzJwR0pxVmJWb3Z0aFN3ZHhRa09xRjIxb2JRZDZJaUpjdkRtbkhTeExvNkRpSEJHWUVZeEpPODNQU2tUWTNYeWg3eVpNQWtVd1wiLFwiZVwiOlwiQVFBQlwiLFwieDVjXCI6W1wiTUlJRkZqQ0NBdjZnQXdJQkFnSVJBSkVyQ0VyUERCaW5VL2JXTGlXblgxb3dEUVlKS29aSWh2Y05BUUVMQlFBd1R6RUxNQWtHQTFVRUJoTUNWVk14S1RBbkJnTlZCQW9USUVsdWRHVnlibVYwSUZObFkzVnlhWFI1SUZKbGMyVmhjbU5vSUVkeWIzVndNUlV3RXdZRFZRUURFd3hKVTFKSElGSnZiM1FnV0RFd0hoY05NakF3T1RBME1EQXdNREF3V2hjTk1qVXdPVEUxTVRZd01EQXdXakF5TVFzd0NRWURWUVFHRXdKVlV6RVdNQlFHQTFVRUNoTU5UR1YwSjNNZ1JXNWpjbmx3ZERFTE1Ba0dBMVVFQXhNQ1VqTXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDN0FoVW96UGFnbE5NUEV1eU5WWkxEK0lMeG1hWjZRb2luWFNhcXRTdTV4VXl4cjQ1citYWElvOWNQUjVRVVZUVlhqSjZvb2prWjlZSThRcWxPYnZVN3d5N2JqY0N3WFBOWk9PZnR6Mm53V2dzYnZzQ1VKQ1dIK2pkeHN4UG5IS3pobSsvYjVEdEZVa1dXcWNGVHpqVElVdTYxcnUyUDNtQnc0cVZVcTdadERwZWxRRFJySzlPOFp1dG1OSHo2YTR1UFZ5bVorREFYWGJweWIvdUJ4YTNTaGxnOUY4Zm5DYnZ4Sy9lRzNNSGFjVjNVUnVQTXJTWEJpTHhnWjNWbXMvRVk5NkpjNWxQL09vaTJSNlgvRXhqcW1BbDNQNTFUK2M4QjVmV21jQmNVcjJPay81bXprNTNjVTZjRy9raUZIYUZwcmlWMXV4UE1VZ1AxN1ZHaGk5c1ZBZ01CQUFHamdnRUlNSUlCQkRBT0JnTlZIUThCQWY4RUJBTUNBWVl3SFFZRFZSMGxCQll3RkFZSUt3WUJCUVVIQXdJR0NDc0dBUVVGQndNQk1CSUdBMVVkRXdFQi93UUlNQVlCQWY4Q0FRQXdIUVlEVlIwT0JCWUVGQlF1c3hlM1dGYkxybEFKUU9ZZnI1MkxGTUxHTUI4R0ExVWRJd1FZTUJhQUZIbTBXZVo3dHVYa0FYT0FDSWpJR2xqMjZadHVNRElHQ0NzR0FRVUZCd0VCQkNZd0pEQWlCZ2dyQmdFRkJRY3dBb1lXYUhSMGNEb3ZMM2d4TG1rdWJHVnVZM0l1YjNKbkx6QW5CZ05WSFI4RUlEQWVNQnlnR3FBWWhoWm9kSFJ3T2k4dmVERXVZeTVzWlc1amNpNXZjbWN2TUNJR0ExVWRJQVFiTUJrd0NBWUdaNEVNQVFJQk1BMEdDeXNHQVFRQmd0OFRBUUVCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFDRnlrNUhQcVAzaFVTRnZOVm5lTEtZWTYxMVRSNldQVE5sY2xRdGdhRHF3KzM0SUw5ZnpMZHdBTGR1Ty9aZWxON2tJSittNzR1eUErZWl0Ulk4a2M2MDdUa0M1M3dsaWtmbVpXNC9SdlRaOE02VUsrNVV6aEs4akNkTHVNR1lMNkt2elhHUlNnaTN5TGdqZXdRdENQa0lWejZEMlFRekNrY2hlQW1DSjhNcXlKdTV6bHp5Wk1qQXZubkFUNDV0UkF4ZWtyc3U5NHNRNGVnZFJDbmJXU0R0WTdraCtCSW1sSk5Yb0IxbEJNRUtJcTRRRFVPWG9SZ2ZmdURnaGplMVdyRzlNTCtIYmlzcS95Rk9Hd1hEOVJpWDhGNnN3Nlc0YXZBdXZEc3p1ZTVMM3N6ODVLK0VDNFkvd0ZWRE52Wm80VFlYYW82WjBmK2xRS2MwdDhEUVl6azFPWFZ1OHJwMnlKTUM2YWxMYkJmT0RBTFp2WUg3bjdkbzFBWmxzNEk5ZDFQNGpua0RyUW94QjNVcVE5aFZsM0xFS1E3M3hGMU95SzVHaEREWDhvVmZHS0Y1dStkZWNJc0g0WWFUdzdtUDNHRnhKU3F2MyswbFVGSm9pNUxjNWRhMTQ5cDkwSWRzaENFeHJvTDErN21yeUlrWFBlRk01VGdPOXIwcnZaYUJGT3ZWMnowZ3AzNVowK0w0V1BsYnVFak4vbHhQRmluK0hsVWpyOGdSc0kzcWZKT1FGeS85cktJSlIwWS84T213dC84b1RXZ3kxbWRlSG1tams3ajFuWXN2QzlKU1E2WnZNbGRsVFRLQjN6aFRoVjErWFdZcDZyamQ1SlcxemJWV0VrTE54RTdHSlRoRVVHM3N6Z0JWR1A3cFNXVFVUc3FYbkxSYndIT29xN2hId2c9PVwiLFwiTUlJRllEQ0NCRWlnQXdJQkFnSVFRQUYzSVRmVTZVSzQ3bmFxUEdRS3R6QU5CZ2txaGtpRzl3MEJBUXNGQURBL01TUXdJZ1lEVlFRS0V4dEVhV2RwZEdGc0lGTnBaMjVoZEhWeVpTQlVjblZ6ZENCRGJ5NHhGekFWQmdOVkJBTVREa1JUVkNCU2IyOTBJRU5CSUZnek1CNFhEVEl4TURFeU1ERTVNVFF3TTFvWERUSTBNRGt6TURFNE1UUXdNMW93VHpFTE1Ba0dBMVVFQmhNQ1ZWTXhLVEFuQmdOVkJBb1RJRWx1ZEdWeWJtVjBJRk5sWTNWeWFYUjVJRkpsYzJWaGNtTm9JRWR5YjNWd01SVXdFd1lEVlFRREV3eEpVMUpISUZKdmIzUWdXREV3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQ0R3QXdnZ0lLQW9JQ0FRQ3Q2Q1J6OUJRMzg1dWVLMWNvSEllKzNMZmZPSkNNYmp6bVY2QjQ5M1hDb3Y3MWFtNzJBRThvMjk1b2hteEVrN2F4WS8wVUVtdS9IOUxxTVpzaGZ0RXpQTHBJOWQxNTM3TzQveEx4SVpwTHdZcUdjV2xLWm1ac2ozNDhjTCt0S1NJRzgrVEE1b0N1NGt1UHQ1bCtsQU9mMDBlWGZKbElJMVBvT0s1UENtK0RMdEZKVjR5QWRMYmFMOUE0alhzRGNDRWJkZkl3UFBxUHJ0M2FZNnZyRmsvQ2poRkxmczhMNlArMWR5NzBzbnRLNEV3U0pReHdqUU1wb09GVEpPd1QyZTRadnhDelNvdy9pYU5oVWQ2c2h3ZVU5R054N0M3aWIxdVlnZUdKWERSNWJIYnZPNUJpZWViYnBKb3ZKc1hRRU9FTzN0a1FqaGI3dC9lbzk4ZmxBZ2VZanpZSWxlZmlONVlOTm5XZSt3NXlzUjJidkFQNVNRWFlnZDBGdENyV1FlbXNBWGFWQ2cvWTM5VzlFaDgxTHlnWGJOS1l3YWdKWkhkdVJ6ZTZ6cXhaWG1pZGYzTFdpY1VHUVNrK1dUN2RKdlVreVJHbldxTk1RQjlHb1ptMXB6cFJib1k3bm4xeXB4SUZlRm50UGxGNEZRc0RqNDNRTHdXeVBudEtIRXR6QlJMOHh1cmdVQk44UTVOMHM4cDA1NDRmQVFqUU1OUmJjVGEwQjdyQk1EQmNTTGVDTzVpbWZXQ0tvcU1wZ3N5NnZZTUVHNktEQTBHaDFnWHhHOEsyOEtoOGhqdEdxRWdxaU54Mm1uYS9IMnFsUFJtUDZ6anpaTjdJS3cwS0tQLzMyK0lWUXRRaTBDZGQ0WG4rR09kd2lLMU81dG1MT3NiZEoxRnUvN3hrOVRORFR3SURBUUFCbzRJQlJqQ0NBVUl3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFPQmdOVkhROEJBZjhFQkFNQ0FRWXdTd1lJS3dZQkJRVUhBUUVFUHpBOU1Ec0dDQ3NHQVFVRkJ6QUNoaTlvZEhSd09pOHZZWEJ3Y3k1cFpHVnVkSEoxYzNRdVkyOXRMM0p2YjNSekwyUnpkSEp2YjNSallYZ3pMbkEzWXpBZkJnTlZIU01FR0RBV2dCVEVwN0drZXl4eCt0dmhTNUIxLzhRVllJV0pFREJVQmdOVkhTQUVUVEJMTUFnR0JtZUJEQUVDQVRBL0Jnc3JCZ0VFQVlMZkV3RUJBVEF3TUM0R0NDc0dBUVVGQndJQkZpSm9kSFJ3T2k4dlkzQnpMbkp2YjNRdGVERXViR1YwYzJWdVkzSjVjSFF1YjNKbk1Ed0dBMVVkSHdRMU1ETXdNYUF2b0MyR0syaDBkSEE2THk5amNtd3VhV1JsYm5SeWRYTjBMbU52YlM5RVUxUlNUMDlVUTBGWU0wTlNUQzVqY213d0hRWURWUjBPQkJZRUZIbTBXZVo3dHVYa0FYT0FDSWpJR2xqMjZadHVNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUFLY3dCc2xtNy9EbExRcnQyTTUxb0dyUytvNDQrL3lRb0RGVkRDNVd4Q3UyK2I5TFJQd2tTSUNIWE02d2ViRkdKdWVON3NKN281WFBXaW9XNVdsSEFRVTdHNzVLL1Fvc01yQWRTVzlNVWdOVFA1MkdFMjRIR050TGkxcW9KRmxjRHlxU01vNTlhaHkyY0kycUJETEtvYmt4L0ozdldyYVYwVDlWdUdXQ0xLVFZYa2NHZHR3bGZGUmpsQno0cFlnMWh0bWY1WDZEWU84QTRqcXYySWw5RGpYQTZVU2JXMUZ6WFNMcjlPaGU4WTRJV1M2d1k3YkNrakNXRGNSUUpNRWhnNzZmc08zdHhFK0ZpWXJ1cTlSVVdoaUYxbXl2NFE2VytDeUJGQ0RmdnA3T09HQU42ZEVPTTQrcVI5c2Rqb1NZS0VCcHNyNkd0UEFRdzRkeTc1M2VjNVwiXSxcImtpZFwiOlwiNjBEX0lYSmF6cGRUTG9fSkhLdk5KMTFxMHFTNjIxbkJsZmlOV3Q3MHRMNFwifSIsInN1YiI6ImRpZDppb246RWlBZU02Tm85a2Rwb3M2X2VoQlVEaDRSSU5ZNFVTRE1oLVFkV2tzbXNJM1drQTpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SW5jd05rOVdOMlUyYmxSMWNuUTJSemxXY0ZaWWVFbDNXVzU1YW1aMWNIaGxSM2xMUWxNdFlteHhkbWNpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVUZTTkdSVlFteHFOV05HYTNkTWRrcFRXVVl6VkV4akxWODFNV2hEWDJ4WmFHeFhaa3hXWjI5c2VUUlJJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsRWNWSnlXVTVmVjNKVGFrRlFkbmxGWWxKUVJWazRXVmhQUm1OdlQwUlRaRXhVVFdJdE0yRktWRWxHUVNJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUVV3eU1GZFlha3BRUVc1NFdXZFFZMVU1UlY5UE9FMU9kSE5wUWswMFFrdHBhVk53VDNaRlRXcFZPVUVpZlgwIiwiYXVkIjoiZGlkOmlvbjpFaUJXZTlSdEhUN1ZaLUp1ZmY4T25uSkF5Rkp0Q29rY1lIeDFDUWtGdHBsN3B3OmV5SmtaV3gwWVNJNmV5SndZWFJqYUdWeklqcGJleUpoWTNScGIyNGlPaUp5WlhCc1lXTmxJaXdpWkc5amRXMWxiblFpT25zaWNIVmliR2xqUzJWNWN5STZXM3NpYVdRaU9pSnJaWGt0TVNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUpGWkRJMU5URTVJaXdpYTNSNUlqb2lUMHRRSWl3aWVDSTZJa05mVDFWS2VFZzJhVWxqUXpaWVpFNW9OMHB0UXkxVVNGaEJWbUZZYm5aMU9VOUZSVm80ZEhFNVRra2lMQ0pyYVdRaU9pSnJaWGt0TVNKOUxDSndkWEp3YjNObGN5STZXeUpoZFhSb1pXNTBhV05oZEdsdmJpSmRMQ0owZVhCbElqb2lTbk52YmxkbFlrdGxlVEl3TWpBaWZWMTlmVjBzSW5Wd1pHRjBaVU52YlcxcGRHMWxiblFpT2lKRmFVTllUa0pxU1daTVZHWk9WME5ITUZRMk0yVmFZbUpFWkZab1NtSlVUamd0U21abGFVeDRkVzFvWlc1M0luMHNJbk4xWm1acGVFUmhkR0VpT25zaVpHVnNkR0ZJWVhOb0lqb2lSV2xDWlZaNVJYQkRiME5QZVhKNlZEaERTSGx2UVcxYWNVMUNUMW8wVlRacWNtMXNkVXQxU2pseFMwcGtaeUlzSW5KbFkyOTJaWEo1UTI5dGJXbDBiV1Z1ZENJNklrVnBRbmhrY0hseWFtbFZTRloxYWtOUldUQktNa2hCVUZGWVpuTndXRkJLWVdsdVYyMW1WM1JOY0ZobmVGRWlmWDAiLCJpc3MiOiJodHRwczovL3NlbGYtaXNzdWVkLm1lL3YyL29wZW5pZC12YyIsImV4cCI6MTY3NDc4NjQ2MywiaWF0IjoxNjc0NzcyMDYzLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsImp0aSI6IjBmNWRhZmVkLTBkODItNDNiMS1hZjc5LTQwNDQwZTNmMTM2NiIsIl92cF90b2tlbiI6eyJkY3FsX3F1ZXJ5Ijoie1wiY3JlZGVudGlhbHNcIjpbe1wiaWRcIjpcIlZlcmlmaWVkRW1wbG95ZWVWQ1wiLFwiZm9ybWF0XCI6XCJ2YytzZC1qd3RcIixcIm1ldGFcIjp7XCJ2Y3RfdmFsdWVzXCI6W1wiaHR0cHM6Ly9oaWdoLWFzc3VyYW5jZS5jb20vVmVyaWZpZWRFbXBsb3llZVZDXCJdfSxcImNsYWltc1wiOlt7XCJwYXRoXCI6W1wibGljZW5zZVwiLFwibnVtYmVyXCJdfSx7XCJwYXRoXCI6W1widXNlclwiLFwibmFtZVwiXX1dfV19In19.lidEc8-wKjpKx_OKdo58nGNImwjzL8lyT5L81dNCj1iauRSPobkahiFo5fddRbTKfKh5Kpatb50bTZNU6iCGeqhvMhHe37n4kK7Ln2ZI8My_CgJx7r2P6VnGNGfA5iKBFlsr5HTCgMFT23Zh4_vx8VdqMPAD7cKGWzk-1BbY7aru8591LoCuVULdjNAJ7hJSHijK2BMcZlxy5n4c7aWvsVp83OJExoNNrRaBXySpckJ9RWscFyMVU9aVsxN0QEHODkCNK5F_3D-ahNrbmHf2_wPJte_ka0QroPRnOgcc6ecja_OlcjdEHJUV-rKnSKyqcDNBm9vZGRPz5FjvdHIoxA'
//'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaWFUbEJkbXBKTUZkalVYbzVORjlhVmtWRGF6VnJTMjFrU0VGRVUyUldOR1JLWjFSTk4wUk9Za05KYXlJc0lua2lPaUpKWkd0eVdrdFVjV2RtTkUxWlkzaFViSGxJTTNaSk1rZEhZakpYWVdNMVowVjFZMGxRYVRGZlJtdG5JbjAjMCJ9.eyJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsImNsaWVudF9pZCI6ImRlY2VudHJhbGl6ZWRfaWRlbnRpZmllcjpkaWQ6aW9uOkVpQldlOVJ0SFQ3VlotSnVmZjhPbm5KQXlGSnRDb2tjWUh4MUNRa0Z0cGw3cHc6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklrTmZUMVZLZUVnMmFVbGpRelpZWkU1b04wcHRReTFVU0ZoQlZtRllibloxT1U5RlJWbzRkSEU1VGtraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVOWVRrSnFTV1pNVkdaT1YwTkhNRlEyTTJWYVltSkVaRlpvU21KVVRqZ3RTbVpsYVV4NGRXMW9aVzUzSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbENaVlo1UlhCRGIwTlBlWEo2VkRoRFNIbHZRVzFhY1UxQ1QxbzBWVFpxY20xc2RVdDFTamx4UzBwa1p5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFuaGtjSGx5YW1sVlNGWjFha05SV1RCS01raEJVRkZZWm5Od1dGQktZV2x1VjIxbVYzUk5jRmhuZUZFaWZYMCIsInJlc3BvbnNlX21vZGUiOiJwb3N0IiwibmJmIjoxNjc0NzcyMDYzLCJzY29wZSI6Im9wZW5pZCIsImNsYWltcyI6eyJ2cF90b2tlbiI6eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6eyJpZCI6IjY0OWQ4YzNjLWY1YWMtNDFiZC05YzE5LTU4MDRlYTFiOGZlOSIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6IlZlcmlmaWVkRW1wbG95ZWVWQyIsIm5hbWUiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJwdXJwb3NlIjoiV2UgbmVlZCB0byB2ZXJpZnkgdGhhdCB5b3UgaGF2ZSBhIFZlcmlmaWVkRW1wbG95ZWUgVmVyaWZpYWJsZSBDcmVkZW50aWFsLiIsInNjaGVtYSI6W3sidXJpIjoiVmVyaWZpZWRFbXBsb3llZSJ9XX1dfX19LCJyZWdpc3RyYXRpb24iOnsiY2xpZW50X25hbWUiOiJFeGFtcGxlIFZlcmlmaWVyIiwidG9zX3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdmVyaWZpZXItaW5mbyIsImxvZ29fdXJpIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS92ZXJpZmllci1pY29uLnBuZyIsInN1YmplY3Rfc3ludGF4X3R5cGVzX3N1cHBvcnRlZCI6WyJkaWQ6aW9uIl0sInZwX2Zvcm1hdHMiOnsiand0X3ZwIjp7ImFsZyI6WyJFZERTQSIsIkVTMjU2SyJdfSwiand0X3ZjIjp7ImFsZyI6WyJFZERTQSIsIkVTMjU2SyJdfX19LCJzdGF0ZSI6IjY0OWQ4YzNjLWY1YWMtNDFiZC05YzE5LTU4MDRlYTFiOGZlOSIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc2lvcC1yZXNwb25zZSIsImV4cCI6MTY3NDc3NTY2MywiaWF0IjoxNjc0NzcyMDYzLCJqdGkiOiJmMGU2ZGNmNS0zZmU2LTQ1MDctYWRjOS1iNDk2ZGFmMzQ1MTIiLCJpc3MiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lhVGxCZG1wSk1GZGpVWG81TkY5YVZrVkRhelZyUzIxa1NFRkVVMlJXTkdSS1oxUk5OMFJPWWtOSmF5SXNJbmtpT2lKSlpHdHlXa3RVY1dkbU5FMVpZM2hVYkhsSU0zWkpNa2RIWWpKWFlXTTFaMFYxWTBsUWFURmZSbXRuSW4wIn0.BFyMTHLatHhJaqQEw4nekU06DZKpuK18-L2ocgAiQTDDoiLafk8QUxACr-Qd2VE18F8AAj7qH2cJbDyzxpG2og'
//'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaWFUbEJkbXBKTUZkalVYbzVORjlhVmtWRGF6VnJTMjFrU0VGRVUyUldOR1JLWjFSTk4wUk9Za05KYXlJc0lua2lPaUpKWkd0eVdrdFVjV2RtTkUxWlkzaFViSGxJTTNaSk1rZEhZakpYWVdNMVowVjFZMGxRYVRGZlJtdG5JbjAjMCJ9.eyJfdnBfdG9rZW4iOnsiZGNxbF9xdWVyeSI6IntcImNyZWRlbnRpYWxzXCI6W3tcImlkXCI6XCJWZXJpZmllZEVtcGxveWVlVkNcIixcInJlcXVpcmVfY3J5cHRvZ3JhcGhpY19ob2xkZXJfYmluZGluZ1wiOnRydWUsXCJtdWx0aXBsZVwiOmZhbHNlLFwiZm9ybWF0XCI6XCJ2YytzZC1qd3RcIixcImNsYWltc1wiOlt7XCJwYXRoXCI6W1wibGljZW5zZVwiLFwibnVtYmVyXCJdfSx7XCJwYXRoXCI6W1widXNlclwiLFwibmFtZVwiXX1dLFwibWV0YVwiOntcInZjdF92YWx1ZXNcIjpbXCJodHRwczovL2hpZ2gtYXNzdXJhbmNlLmNvbS9WZXJpZmllZEVtcGxveWVlVkNcIl19fV19In0sImF1ZCI6ImRpZDppb246RWlCV2U5UnRIVDdWWi1KdWZmOE9ubkpBeUZKdENva2NZSHgxQ1FrRnRwbDdwdzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtOZlQxVktlRWcyYVVsalF6WllaRTVvTjBwdFF5MVVTRmhCVm1GWWJuWjFPVTlGUlZvNGRIRTVUa2tpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5ZVGtKcVNXWk1WR1pPVjBOSE1GUTJNMlZhWW1KRVpGWm9TbUpVVGpndFNtWmxhVXg0ZFcxb1pXNTNJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQ1pWWjVSWEJEYjBOUGVYSjZWRGhEU0hsdlFXMWFjVTFDVDFvMFZUWnFjbTFzZFV0MVNqbHhTMHBrWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUW5oa2NIbHlhbWxWU0ZaMWFrTlJXVEJLTWtoQlVGRllabk53V0ZCS1lXbHVWMjFtVjNSTmNGaG5lRkVpZlgwIiwiZXhwIjoxNjc0Nzg2NDYzLCJpYXQiOjE2NzQ3NzIwNjMsImlzcyI6Imh0dHBzOi8vc2VsZi1pc3N1ZWQubWUvdjIvb3BlbmlkLXZjIiwianRpIjoiMGY1ZGFmZWQtMGQ4Mi00M2IxLWFmNzktNDA0NDBlM2YxMzY2Iiwibm9uY2UiOiI0MDI1MmFmYy02YTgyLTRhMmUtOTA1Zi1lNDFmMTIyZWY1NzUifQ.natbNPw4CmCV5vnK781KUFH-Ypgx8Uj4MOG2RHargcU-gSFRbMdOY-YcJrGvFVpEmKfG_zLFg5a6WGDkbVby_g'
//'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaWFUbEJkbXBKTUZkalVYbzVORjlhVmtWRGF6VnJTMjFrU0VGRVUyUldOR1JLWjFSTk4wUk9Za05KYXlJc0lua2lPaUpKWkd0eVdrdFVjV2RtTkUxWlkzaFViSGxJTTNaSk1rZEhZakpYWVdNMVowVjFZMGxRYVRGZlJtdG5JbjAjMCJ9.eyJfdnBfdG9rZW4iOnsiZGNxbF9xdWVyeSI6IntcImNyZWRlbnRpYWxzXCI6W3tcImlkXCI6XCJWZXJpZmllZEVtcGxveWVlVkNcIixcInJlcXVpcmVfY3J5cHRvZ3JhcGhpY19ob2xkZXJfYmluZGluZ1wiOnRydWUsXCJtdWx0aXBsZVwiOmZhbHNlLFwiZm9ybWF0XCI6XCJ2YytzZC1qd3RcIixcImNsYWltc1wiOlt7XCJwYXRoXCI6W1wibGljZW5zZVwiLFwibnVtYmVyXCJdfSx7XCJwYXRoXCI6W1widXNlclwiLFwibmFtZVwiXX1dLFwibWV0YVwiOntcInZjdF92YWx1ZXNcIjpbXCJodHRwczovL2hpZ2gtYXNzdXJhbmNlLmNvbS9WZXJpZmllZEVtcGxveWVlVkNcIl19fV19In0sImF1ZCI6ImRpZDppb246RWlCV2U5UnRIVDdWWi1KdWZmOE9ubkpBeUZKdENva2NZSHgxQ1FrRnRwbDdwdzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtOZlQxVktlRWcyYVVsalF6WllaRTVvTjBwdFF5MVVTRmhCVm1GWWJuWjFPVTlGUlZvNGRIRTVUa2tpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5ZVGtKcVNXWk1WR1pPVjBOSE1GUTJNMlZhWW1KRVpGWm9TbUpVVGpndFNtWmxhVXg0ZFcxb1pXNTNJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQ1pWWjVSWEJEYjBOUGVYSjZWRGhEU0hsdlFXMWFjVTFDVDFvMFZUWnFjbTFzZFV0MVNqbHhTMHBrWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUW5oa2NIbHlhbWxWU0ZaMWFrTlJXVEJLTWtoQlVGRllabk53V0ZCS1lXbHVWMjFtVjNSTmNGaG5lRkVpZlgwIiwiZXhwIjoxNjc0Nzg2NDYzLCJpYXQiOjE2NzQ3NzIwNjMsImlzcyI6Imh0dHBzOi8vc2VsZi1pc3N1ZWQubWUvdjIvb3BlbmlkLXZjIiwianRpIjoiMGY1ZGFmZWQtMGQ4Mi00M2IxLWFmNzktNDA0NDBlM2YxMzY2Iiwibm9uY2UiOiI0MDI1MmFmYy02YTgyLTRhMmUtOTA1Zi1lNDFmMTIyZWY1NzUiLCJzdWIiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCIsInN1Yl9qd2siOiJ7XCJrdHlcIjpcIlJTQVwiLFwiblwiOlwiMWVzZmh3aVJTcEZZRzNsRnN2WWdsamhadFNlYnpaMnpnd3pHckJ6NDZmSnV6NDlzd2FuWkZMQ1otdG5FeERZQUNORy1sUWY0azdhc01xWFdGRU1VMm94SVoxSnZfUlhrSF9MNF9BdC1EaVBQTkQzb1lIcjRna0t3cFZxeTg0dzNIQkw2RUZVaXJjX0FOV00zTjBxcnNQTGtIeFNsYWp3Z3lzdXAxWTRVM2d4NF9iY1FTVTM2SmhfbG1CNlE5N0xwa1Y3dHhnZWNXVUJzQXVoOXQzSzJpYVZkVWNOd184LTV4WmFwWVBRRUdjRXA0N3lQaXhPSjJTbVhwb1IyaVRwdlpLNFpOeUYzSnhxS1FnMnBHSnFWYlZvdnRoU3dkeFFrT3FGMjFvYlFkNklpSmN2RG1uSFN4TG82RGlIQkdZRVl4Sk84M1BTa1RZM1h5aDd5Wk1Ba1V3XCIsXCJlXCI6XCJBUUFCXCIsXCJ4NWNcIjpbXCJNSUlGRmpDQ0F2NmdBd0lCQWdJUkFKRXJDRXJQREJpblUvYldMaVduWDFvd0RRWUpLb1pJaHZjTkFRRUxCUUF3VHpFTE1Ba0dBMVVFQmhNQ1ZWTXhLVEFuQmdOVkJBb1RJRWx1ZEdWeWJtVjBJRk5sWTNWeWFYUjVJRkpsYzJWaGNtTm9JRWR5YjNWd01SVXdFd1lEVlFRREV3eEpVMUpISUZKdmIzUWdXREV3SGhjTk1qQXdPVEEwTURBd01EQXdXaGNOTWpVd09URTFNVFl3TURBd1dqQXlNUXN3Q1FZRFZRUUdFd0pWVXpFV01CUUdBMVVFQ2hNTlRHVjBKM01nUlc1amNubHdkREVMTUFrR0ExVUVBeE1DVWpNd2dnRWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUM3QWhVb3pQYWdsTk1QRXV5TlZaTEQrSUx4bWFaNlFvaW5YU2FxdFN1NXhVeXhyNDVyK1hYSW85Y1BSNVFVVlRWWGpKNm9vamtaOVlJOFFxbE9idlU3d3k3YmpjQ3dYUE5aT09mdHoybndXZ3NidnNDVUpDV0gramR4c3hQbkhLemhtKy9iNUR0RlVrV1dxY0ZUempUSVV1NjFydTJQM21CdzRxVlVxN1p0RHBlbFFEUnJLOU84WnV0bU5IejZhNHVQVnltWitEQVhYYnB5Yi91QnhhM1NobGc5RjhmbkNidnhLL2VHM01IYWNWM1VSdVBNclNYQmlMeGdaM1Ztcy9FWTk2SmM1bFAvT29pMlI2WC9FeGpxbUFsM1A1MVQrYzhCNWZXbWNCY1VyMk9rLzVtems1M2NVNmNHL2tpRkhhRnByaVYxdXhQTVVnUDE3VkdoaTlzVkFnTUJBQUdqZ2dFSU1JSUJCREFPQmdOVkhROEJBZjhFQkFNQ0FZWXdIUVlEVlIwbEJCWXdGQVlJS3dZQkJRVUhBd0lHQ0NzR0FRVUZCd01CTUJJR0ExVWRFd0VCL3dRSU1BWUJBZjhDQVFBd0hRWURWUjBPQkJZRUZCUXVzeGUzV0ZiTHJsQUpRT1lmcjUyTEZNTEdNQjhHQTFVZEl3UVlNQmFBRkhtMFdlWjd0dVhrQVhPQUNJaklHbGoyNlp0dU1ESUdDQ3NHQVFVRkJ3RUJCQ1l3SkRBaUJnZ3JCZ0VGQlFjd0FvWVdhSFIwY0RvdkwzZ3hMbWt1YkdWdVkzSXViM0puTHpBbkJnTlZIUjhFSURBZU1CeWdHcUFZaGhab2RIUndPaTh2ZURFdVl5NXNaVzVqY2k1dmNtY3ZNQ0lHQTFVZElBUWJNQmt3Q0FZR1o0RU1BUUlCTUEwR0N5c0dBUVFCZ3Q4VEFRRUJNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUNBUUNGeWs1SFBxUDNoVVNGdk5WbmVMS1lZNjExVFI2V1BUTmxjbFF0Z2FEcXcrMzRJTDlmekxkd0FMZHVPL1plbE43a0lKK203NHV5QStlaXRSWThrYzYwN1RrQzUzd2xpa2ZtWlc0L1J2VFo4TTZVSys1VXpoSzhqQ2RMdU1HWUw2S3Z6WEdSU2dpM3lMZ2pld1F0Q1BrSVZ6NkQyUVF6Q2tjaGVBbUNKOE1xeUp1NXpsenlaTWpBdm5uQVQ0NXRSQXhla3JzdTk0c1E0ZWdkUkNuYldTRHRZN2toK0JJbWxKTlhvQjFsQk1FS0lxNFFEVU9Yb1JnZmZ1RGdoamUxV3JHOU1MK0hiaXNxL3lGT0d3WEQ5UmlYOEY2c3c2VzRhdkF1dkRzenVlNUwzc3o4NUsrRUM0WS93RlZETnZabzRUWVhhbzZaMGYrbFFLYzB0OERRWXprMU9YVnU4cnAyeUpNQzZhbExiQmZPREFMWnZZSDduN2RvMUFabHM0STlkMVA0am5rRHJRb3hCM1VxUTloVmwzTEVLUTczeEYxT3lLNUdoRERYOG9WZkdLRjV1K2RlY0lzSDRZYVR3N21QM0dGeEpTcXYzKzBsVUZKb2k1TGM1ZGExNDlwOTBJZHNoQ0V4cm9MMSs3bXJ5SWtYUGVGTTVUZ085cjBydlphQkZPdlYyejBncDM1WjArTDRXUGxidUVqTi9seFBGaW4rSGxVanI4Z1JzSTNxZkpPUUZ5LzlyS0lKUjBZLzhPbXd0LzhvVFdneTFtZGVIbW1qazdqMW5Zc3ZDOUpTUTZadk1sZGxUVEtCM3poVGhWMStYV1lwNnJqZDVKVzF6YlZXRWtMTnhFN0dKVGhFVUczc3pnQlZHUDdwU1dUVVRzcVhuTFJid0hPb3E3aEh3Zz09XCIsXCJNSUlGWURDQ0JFaWdBd0lCQWdJUVFBRjNJVGZVNlVLNDduYXFQR1FLdHpBTkJna3Foa2lHOXcwQkFRc0ZBREEvTVNRd0lnWURWUVFLRXh0RWFXZHBkR0ZzSUZOcFoyNWhkSFZ5WlNCVWNuVnpkQ0JEYnk0eEZ6QVZCZ05WQkFNVERrUlRWQ0JTYjI5MElFTkJJRmd6TUI0WERUSXhNREV5TURFNU1UUXdNMW9YRFRJME1Ea3pNREU0TVRRd00xb3dUekVMTUFrR0ExVUVCaE1DVlZNeEtUQW5CZ05WQkFvVElFbHVkR1Z5Ym1WMElGTmxZM1Z5YVhSNUlGSmxjMlZoY21Ob0lFZHliM1Z3TVJVd0V3WURWUVFERXd4SlUxSkhJRkp2YjNRZ1dERXdnZ0lpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElDRHdBd2dnSUtBb0lDQVFDdDZDUno5QlEzODV1ZUsxY29ISWUrM0xmZk9KQ01ianptVjZCNDkzWENvdjcxYW03MkFFOG8yOTVvaG14RWs3YXhZLzBVRW11L0g5THFNWnNoZnRFelBMcEk5ZDE1MzdPNC94THhJWnBMd1lxR2NXbEtabVpzajM0OGNMK3RLU0lHOCtUQTVvQ3U0a3VQdDVsK2xBT2YwMGVYZkpsSUkxUG9PSzVQQ20rREx0RkpWNHlBZExiYUw5QTRqWHNEY0NFYmRmSXdQUHFQcnQzYVk2dnJGay9DamhGTGZzOEw2UCsxZHk3MHNudEs0RXdTSlF4d2pRTXBvT0ZUSk93VDJlNFp2eEN6U293L2lhTmhVZDZzaHdlVTlHTng3QzdpYjF1WWdlR0pYRFI1Ykhidk81QmllZWJicEpvdkpzWFFFT0VPM3RrUWpoYjd0L2VvOThmbEFnZVlqellJbGVmaU41WU5ObldlK3c1eXNSMmJ2QVA1U1FYWWdkMEZ0Q3JXUWVtc0FYYVZDZy9ZMzlXOUVoODFMeWdYYk5LWXdhZ0paSGR1UnplNnpxeFpYbWlkZjNMV2ljVUdRU2srV1Q3ZEp2VWt5UkduV3FOTVFCOUdvWm0xcHpwUmJvWTdubjF5cHhJRmVGbnRQbEY0RlFzRGo0M1FMd1d5UG50S0hFdHpCUkw4eHVyZ1VCTjhRNU4wczhwMDU0NGZBUWpRTU5SYmNUYTBCN3JCTURCY1NMZUNPNWltZldDS29xTXBnc3k2dllNRUc2S0RBMEdoMWdYeEc4SzI4S2g4aGp0R3FFZ3FpTngybW5hL0gycWxQUm1QNnpqelpON0lLdzBLS1AvMzIrSVZRdFFpMENkZDRYbitHT2R3aUsxTzV0bUxPc2JkSjFGdS83eGs5VE5EVHdJREFRQUJvNElCUmpDQ0FVSXdEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU9CZ05WSFE4QkFmOEVCQU1DQVFZd1N3WUlLd1lCQlFVSEFRRUVQekE5TURzR0NDc0dBUVVGQnpBQ2hpOW9kSFJ3T2k4dllYQndjeTVwWkdWdWRISjFjM1F1WTI5dEwzSnZiM1J6TDJSemRISnZiM1JqWVhnekxuQTNZekFmQmdOVkhTTUVHREFXZ0JURXA3R2tleXh4K3R2aFM1QjEvOFFWWUlXSkVEQlVCZ05WSFNBRVRUQkxNQWdHQm1lQkRBRUNBVEEvQmdzckJnRUVBWUxmRXdFQkFUQXdNQzRHQ0NzR0FRVUZCd0lCRmlKb2RIUndPaTh2WTNCekxuSnZiM1F0ZURFdWJHVjBjMlZ1WTNKNWNIUXViM0puTUR3R0ExVWRId1ExTURNd01hQXZvQzJHSzJoMGRIQTZMeTlqY213dWFXUmxiblJ5ZFhOMExtTnZiUzlFVTFSU1QwOVVRMEZZTTBOU1RDNWpjbXd3SFFZRFZSME9CQllFRkhtMFdlWjd0dVhrQVhPQUNJaklHbGoyNlp0dU1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQUtjd0JzbG03L0RsTFFydDJNNTFvR3JTK280NCsveVFvREZWREM1V3hDdTIrYjlMUlB3a1NJQ0hYTTZ3ZWJGR0p1ZU43c0o3bzVYUFdpb1c1V2xIQVFVN0c3NUsvUW9zTXJBZFNXOU1VZ05UUDUyR0UyNEhHTnRMaTFxb0pGbGNEeXFTTW81OWFoeTJjSTJxQkRMS29ia3gvSjN2V3JhVjBUOVZ1R1dDTEtUVlhrY0dkdHdsZkZSamxCejRwWWcxaHRtZjVYNkRZTzhBNGpxdjJJbDlEalhBNlVTYlcxRnpYU0xyOU9oZThZNElXUzZ3WTdiQ2tqQ1dEY1JRSk1FaGc3NmZzTzN0eEUrRmlZcnVxOVJVV2hpRjFteXY0UTZXK0N5QkZDRGZ2cDdPT0dBTjZkRU9NNCtxUjlzZGpvU1lLRUJwc3I2R3RQQVF3NGR5NzUzZWM1XCJdLFwia2lkXCI6XCI2MERfSVhKYXpwZFRMb19KSEt2TkoxMXEwcVM2MjFuQmxmaU5XdDcwdEw0XCJ9In0.wpqJ7HdKae8IF4KEqEa4C2vTvt9sB69d0YW7t7YXD2b15Qs0TmDayl5AYbD6gbUxeAMXz54G2SgB75HZpSnIRw'
//'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaWFUbEJkbXBKTUZkalVYbzVORjlhVmtWRGF6VnJTMjFrU0VGRVUyUldOR1JLWjFSTk4wUk9Za05KYXlJc0lua2lPaUpKWkd0eVdrdFVjV2RtTkUxWlkzaFViSGxJTTNaSk1rZEhZakpYWVdNMVowVjFZMGxRYVRGZlJtdG5JbjAjMCJ9.eyJfdnBfdG9rZW4iOnsiZGNxbF9xdWVyeSI6IntcImNyZWRlbnRpYWxzXCI6W3tcImlkXCI6XCJWZXJpZmllZEVtcGxveWVlVkNcIixcInJlcXVpcmVfY3J5cHRvZ3JhcGhpY19ob2xkZXJfYmluZGluZ1wiOnRydWUsXCJtdWx0aXBsZVwiOmZhbHNlLFwiZm9ybWF0XCI6XCJ2YytzZC1qd3RcIixcImNsYWltc1wiOlt7XCJwYXRoXCI6W1wibGljZW5zZVwiLFwibnVtYmVyXCJdfSx7XCJwYXRoXCI6W1widXNlclwiLFwibmFtZVwiXX1dLFwibWV0YVwiOntcInZjdF92YWx1ZXNcIjpbXCJodHRwczovL2hpZ2gtYXNzdXJhbmNlLmNvbS9WZXJpZmllZEVtcGxveWVlVkNcIl19fV19In0sImF1ZCI6ImRpZDppb246RWlCV2U5UnRIVDdWWi1KdWZmOE9ubkpBeUZKdENva2NZSHgxQ1FrRnRwbDdwdzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtOZlQxVktlRWcyYVVsalF6WllaRTVvTjBwdFF5MVVTRmhCVm1GWWJuWjFPVTlGUlZvNGRIRTVUa2tpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5ZVGtKcVNXWk1WR1pPVjBOSE1GUTJNMlZhWW1KRVpGWm9TbUpVVGpndFNtWmxhVXg0ZFcxb1pXNTNJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQ1pWWjVSWEJEYjBOUGVYSjZWRGhEU0hsdlFXMWFjVTFDVDFvMFZUWnFjbTFzZFV0MVNqbHhTMHBrWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUW5oa2NIbHlhbWxWU0ZaMWFrTlJXVEJLTWtoQlVGRllabk53V0ZCS1lXbHVWMjFtVjNSTmNGaG5lRkVpZlgwIiwiZXhwIjoxNjc0Nzg2NDYzLCJpYXQiOjE2NzQ3NzIwNjMsImlzcyI6Imh0dHBzOi8vc2VsZi1pc3N1ZWQubWUvdjIvb3BlbmlkLXZjIiwianRpIjoiMGY1ZGFmZWQtMGQ4Mi00M2IxLWFmNzktNDA0NDBlM2YxMzY2Iiwibm9uY2UiOiI0MDI1MmFmYy02YTgyLTRhMmUtOTA1Zi1lNDFmMTIyZWY1NzUiLCJzdWIiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCJ9.S94aFwraZkcNLgqnzuSjntAqeyQiBiTQYqhX3KX0TObdpriQ4xS1hNBaVOGB8AV4kU3eL8t3EDBJGRyBnYTgaw'
'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaWFUbEJkbXBKTUZkalVYbzVORjlhVmtWRGF6VnJTMjFrU0VGRVUyUldOR1JLWjFSTk4wUk9Za05KYXlJc0lua2lPaUpKWkd0eVdrdFVjV2RtTkUxWlkzaFViSGxJTTNaSk1rZEhZakpYWVdNMVowVjFZMGxRYVRGZlJtdG5JbjAjMCJ9.eyJfdnBfdG9rZW4iOnsiZGNxbF9xdWVyeSI6IntcImNyZWRlbnRpYWxzXCI6W3tcImlkXCI6XCJWZXJpZmllZEVtcGxveWVlVkNcIixcInJlcXVpcmVfY3J5cHRvZ3JhcGhpY19ob2xkZXJfYmluZGluZ1wiOnRydWUsXCJtdWx0aXBsZVwiOmZhbHNlLFwiZm9ybWF0XCI6XCJ2YytzZC1qd3RcIixcImNsYWltc1wiOlt7XCJwYXRoXCI6W1wibGljZW5zZVwiLFwibnVtYmVyXCJdfSx7XCJwYXRoXCI6W1widXNlclwiLFwibmFtZVwiXX1dLFwibWV0YVwiOntcInZjdF92YWx1ZXNcIjpbXCJodHRwczovL2hpZ2gtYXNzdXJhbmNlLmNvbS9WZXJpZmllZEVtcGxveWVlVkNcIl19fV19In0sImF1ZCI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaWFUbEJkbXBKTUZkalVYbzVORjlhVmtWRGF6VnJTMjFrU0VGRVUyUldOR1JLWjFSTk4wUk9Za05KYXlJc0lua2lPaUpKWkd0eVdrdFVjV2RtTkUxWlkzaFViSGxJTTNaSk1rZEhZakpYWVdNMVowVjFZMGxRYVRGZlJtdG5JbjAiLCJleHAiOjE2NzQ3ODY0NjMsImlhdCI6MTY3NDc3MjA2MywiaXNzIjoiaHR0cHM6Ly9zZWxmLWlzc3VlZC5tZS92Mi9vcGVuaWQtdmMiLCJqdGkiOiIwZjVkYWZlZC0wZDgyLTQzYjEtYWY3OS00MDQ0MGUzZjEzNjYiLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsInN1YiI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaWFUbEJkbXBKTUZkalVYbzVORjlhVmtWRGF6VnJTMjFrU0VGRVUyUldOR1JLWjFSTk4wUk9Za05KYXlJc0lua2lPaUpKWkd0eVdrdFVjV2RtTkUxWlkzaFViSGxJTTNaSk1rZEhZakpYWVdNMVowVjFZMGxRYVRGZlJtdG5JbjAifQ.fXqCDnzLvMiHdq8pq2ipMRR0Yd6GnsEmMEKJ7C0JV2y_AnjqXk-jz_7_7o2owFmF_snBG_0LW6mpGDyB7v745A'

  public static dcqlQuery = { // TODO
    credentials: [
      {
        id: 'VerifiedEmployeeVC',
        format: 'vc+sd-jwt',
        meta: {
          vct_values: ['https://high-assurance.com/VerifiedEmployeeVC'],
        },
        claims: [{ path: ['license', 'number'] }, { path: ['user', 'name'] }],
      },
    ],
  } satisfies DcqlQuery.Input
  public static parsedDcqlQuery = DcqlQuery.parse(this.dcqlQuery)

  public static idTokenPayload = {
    //sub: 'did:ion:EiAeM6No9kdpos6_ehBUDh4RINY4USDMh-QdWksmsI3WkA:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IncwNk9WN2U2blR1cnQ2RzlWcFZYeEl3WW55amZ1cHhlR3lLQlMtYmxxdmciLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUFSNGRVQmxqNWNGa3dMdkpTWUYzVExjLV81MWhDX2xZaGxXZkxWZ29seTRRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlEcVJyWU5fV3JTakFQdnlFYlJQRVk4WVhPRmNvT0RTZExUTWItM2FKVElGQSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQUwyMFdYakpQQW54WWdQY1U5RV9POE1OdHNpQk00QktpaVNwT3ZFTWpVOUEifX0',
    sub: "did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiaTlBdmpJMFdjUXo5NF9aVkVDazVrS21kSEFEU2RWNGRKZ1RNN0ROYkNJayIsInkiOiJJZGtyWktUcWdmNE1ZY3hUbHlIM3ZJMkdHYjJXYWM1Z0V1Y0lQaTFfRmtnIn0",
    //aud: 'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0',
    aud: "did:jwk:eyJhbGciOiJFUzI1NiIsInVzZSI6InNpZyIsImt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiaTlBdmpJMFdjUXo5NF9aVkVDazVrS21kSEFEU2RWNGRKZ1RNN0ROYkNJayIsInkiOiJJZGtyWktUcWdmNE1ZY3hUbHlIM3ZJMkdHYjJXYWM1Z0V1Y0lQaTFfRmtnIn0",
    iss: 'https://self-issued.me/v2/openid-vc',
    exp: 1674786463,
    iat: 1674772063,
    nonce: '40252afc-6a82-4a2e-905f-e41f122ef575',
    jti: '0f5dafed-0d82-43b1-af79-40440e3f1366',
    // sub_jwk: "{\"kty\":\"RSA\",\"n\":\"1esfhwiRSpFYG3lFsvYgljhZtSebzZ2zgwzGrBz46fJuz49swanZFLCZ-tnExDYACNG-lQf4k7asMqXWFEMU2oxIZ1Jv_RXkH_L4_At-DiPPND3oYHr4gkKwpVqy84w3HBL6EFUirc_ANWM3N0qrsPLkHxSlajwgysup1Y4U3gx4_bcQSU36Jh_lmB6Q97LpkV7txgecWUBsAuh9t3K2iaVdUcNw_8-5xZapYPQEGcEp47yPixOJ2SmXpoR2iTpvZK4ZNyF3JxqKQg2pGJqVbVovthSwdxQkOqF21obQd6IiJcvDmnHSxLo6DiHBGYEYxJO83PSkTY3Xyh7yZMAkUw\",\"e\":\"AQAB\",\"x5c\":[\"MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAwTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAwWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3MgRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cPR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdxsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8ZutmNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxgZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaAFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQBgt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6WPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wlikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQzCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BImlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1OyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90IdshCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6ZvMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqXnLRbwHOoq7hHwg==\",\"MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1owTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XCov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpLwYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+DLtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5ysR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZXmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBcSLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2qlPRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TNDTwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEBATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQub3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9EU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26ZtuMA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuGWCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9Ohe8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFCDfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5\"],\"kid\":\"60D_IXJazpdTLo_JHKvNJ11q0qS621nBlfiNWt70tL4\"}",
    _vp_token: {
      dcql_query: JSON.stringify(TestVectors.parsedDcqlQuery) //
    }
  }

  public static requestObjectJwt =
    // 'eyJraWQiOiJkaWQ6aW9uOkVpQldlOVJ0SFQ3VlotSnVmZjhPbm5KQXlGSnRDb2tjWUh4MUNRa0Z0cGw3cHc6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklrTmZUMVZLZUVnMmFVbGpRelpZWkU1b04wcHRReTFVU0ZoQlZtRllibloxT1U5RlJWbzRkSEU1VGtraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVOWVRrSnFTV1pNVkdaT1YwTkhNRlEyTTJWYVltSkVaRlpvU21KVVRqZ3RTbVpsYVV4NGRXMW9aVzUzSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbENaVlo1UlhCRGIwTlBlWEo2VkRoRFNIbHZRVzFhY1UxQ1QxbzBWVFpxY20xc2RVdDFTamx4UzBwa1p5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFuaGtjSGx5YW1sVlNGWjFha05SV1RCS01raEJVRkZZWm5Od1dGQktZV2x1VjIxbVYzUk5jRmhuZUZFaWZYMCNrZXktMSIsInR5cCI6IkpXVCIsImFsZyI6IkVkRFNBIn0.eyJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsImNsaWVudF9pZCI6ImRpZDppb246RWlCV2U5UnRIVDdWWi1KdWZmOE9ubkpBeUZKdENva2NZSHgxQ1FrRnRwbDdwdzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtOZlQxVktlRWcyYVVsalF6WllaRTVvTjBwdFF5MVVTRmhCVm1GWWJuWjFPVTlGUlZvNGRIRTVUa2tpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5ZVGtKcVNXWk1WR1pPVjBOSE1GUTJNMlZhWW1KRVpGWm9TbUpVVGpndFNtWmxhVXg0ZFcxb1pXNTNJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQ1pWWjVSWEJEYjBOUGVYSjZWRGhEU0hsdlFXMWFjVTFDVDFvMFZUWnFjbTFzZFV0MVNqbHhTMHBrWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUW5oa2NIbHlhbWxWU0ZaMWFrTlJXVEJLTWtoQlVGRllabk53V0ZCS1lXbHVWMjFtVjNSTmNGaG5lRkVpZlgwIiwicmVzcG9uc2VfbW9kZSI6InBvc3QiLCJuYmYiOjE2NzQ3NzIwNjMsInNjb3BlIjoib3BlbmlkIiwiY2xhaW1zIjp7InZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiNjQ5ZDhjM2MtZjVhYy00MWJkLTljMTktNTgwNGVhMWI4ZmU5IiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiVmVyaWZpZWRFbXBsb3llZVZDIiwibmFtZSI6IlZlcmlmaWVkRW1wbG95ZWVWQyIsInB1cnBvc2UiOiJXZSBuZWVkIHRvIHZlcmlmeSB0aGF0IHlvdSBoYXZlIGEgVmVyaWZpZWRFbXBsb3llZSBWZXJpZmlhYmxlIENyZWRlbnRpYWwuIiwic2NoZW1hIjpbeyJ1cmkiOiJWZXJpZmllZEVtcGxveWVlIn1dfV19fX0sInJlZ2lzdHJhdGlvbiI6eyJjbGllbnRfbmFtZSI6IkV4YW1wbGUgVmVyaWZpZXIiLCJ0b3NfdXJpIjoiaHR0cHM6XC9cL2V4YW1wbGUuY29tXC92ZXJpZmllci1pbmZvIiwibG9nb191cmkiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL3ZlcmlmaWVyLWljb24ucG5nIiwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbImRpZDppb24iXSwidnBfZm9ybWF0cyI6eyJqd3RfdnAiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTZLIl19LCJqd3RfdmMiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTZLIl19fX0sInN0YXRlIjoiNjQ5ZDhjM2MtZjVhYy00MWJkLTljMTktNTgwNGVhMWI4ZmU5IiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6XC9cL2V4YW1wbGUuY29tXC9zaW9wLXJlc3BvbnNlIiwiZXhwIjoxNjc0Nzc1NjYzLCJpYXQiOjE2NzQ3NzIwNjMsImp0aSI6ImYwZTZkY2Y1LTNmZTYtNDUwNy1hZGM5LWI0OTZkYWYzNDUxMiJ9.znX9h8l8JYoy8BHlnZzRDBEpaAv3hkb_XfUEzG-9eZID3tJjJdrO7PAr4kTay-nxvMhkzNsQg1rCZsjOMbKbBg'
    'eyJraWQiOiJkaWQ6aW9uOkVpQldlOVJ0SFQ3VlotSnVmZjhPbm5KQXlGSnRDb2tjWUh4MUNRa0Z0cGw3cHc6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklrTmZUMVZLZUVnMmFVbGpRelpZWkU1b04wcHRReTFVU0ZoQlZtRllibloxT1U5RlJWbzRkSEU1VGtraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVOWVRrSnFTV1pNVkdaT1YwTkhNRlEyTTJWYVltSkVaRlpvU21KVVRqZ3RTbVpsYVV4NGRXMW9aVzUzSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbENaVlo1UlhCRGIwTlBlWEo2VkRoRFNIbHZRVzFhY1UxQ1QxbzBWVFpxY20xc2RVdDFTamx4UzBwa1p5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFuaGtjSGx5YW1sVlNGWjFha05SV1RCS01raEJVRkZZWm5Od1dGQktZV2x1VjIxbVYzUk5jRmhuZUZFaWZYMCNrZXktMSIsInR5cCI6IkpXVCIsImFsZyI6IkVkRFNBIn0.eyJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsImNsaWVudF9pZCI6ImRlY2VudHJhbGl6ZWRfaWRlbnRpZmllcjpkaWQ6aW9uOkVpQldlOVJ0SFQ3VlotSnVmZjhPbm5KQXlGSnRDb2tjWUh4MUNRa0Z0cGw3cHc6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklrTmZUMVZLZUVnMmFVbGpRelpZWkU1b04wcHRReTFVU0ZoQlZtRllibloxT1U5RlJWbzRkSEU1VGtraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVOWVRrSnFTV1pNVkdaT1YwTkhNRlEyTTJWYVltSkVaRlpvU21KVVRqZ3RTbVpsYVV4NGRXMW9aVzUzSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbENaVlo1UlhCRGIwTlBlWEo2VkRoRFNIbHZRVzFhY1UxQ1QxbzBWVFpxY20xc2RVdDFTamx4UzBwa1p5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFuaGtjSGx5YW1sVlNGWjFha05SV1RCS01raEJVRkZZWm5Od1dGQktZV2x1VjIxbVYzUk5jRmhuZUZFaWZYMCIsInJlc3BvbnNlX21vZGUiOiJwb3N0IiwibmJmIjoxNjc0NzcyMDYzLCJzY29wZSI6Im9wZW5pZCIsImNsYWltcyI6eyJ2cF90b2tlbiI6eyJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6eyJpZCI6IjY0OWQ4YzNjLWY1YWMtNDFiZC05YzE5LTU4MDRlYTFiOGZlOSIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6IlZlcmlmaWVkRW1wbG95ZWVWQyIsIm5hbWUiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJwdXJwb3NlIjoiV2UgbmVlZCB0byB2ZXJpZnkgdGhhdCB5b3UgaGF2ZSBhIFZlcmlmaWVkRW1wbG95ZWUgVmVyaWZpYWJsZSBDcmVkZW50aWFsLiIsInNjaGVtYSI6W3sidXJpIjoiVmVyaWZpZWRFbXBsb3llZSJ9XX1dfX19LCJyZWdpc3RyYXRpb24iOnsiY2xpZW50X25hbWUiOiJFeGFtcGxlIFZlcmlmaWVyIiwidG9zX3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vdmVyaWZpZXItaW5mbyIsImxvZ29fdXJpIjoiaHR0cHM6Ly9leGFtcGxlLmNvbS92ZXJpZmllci1pY29uLnBuZyIsInN1YmplY3Rfc3ludGF4X3R5cGVzX3N1cHBvcnRlZCI6WyJkaWQ6aW9uIl0sInZwX2Zvcm1hdHMiOnsiand0X3ZwIjp7ImFsZyI6WyJFZERTQSIsIkVTMjU2SyJdfSwiand0X3ZjIjp7ImFsZyI6WyJFZERTQSIsIkVTMjU2SyJdfX19LCJzdGF0ZSI6IjY0OWQ4YzNjLWY1YWMtNDFiZC05YzE5LTU4MDRlYTFiOGZlOSIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vc2lvcC1yZXNwb25zZSIsImV4cCI6MTY3NDc3NTY2MywiaWF0IjoxNjc0NzcyMDYzLCJqdGkiOiJmMGU2ZGNmNS0zZmU2LTQ1MDctYWRjOS1iNDk2ZGFmMzQ1MTIifQ.ArOKioxCen89_mqWeqzwZrRd_BBIghrXUMPUH-PHUTbtl-ycUKcXc3Kh6EAfC5kj45dB0wrA4x24W9ZjJarEAQ'

  public static requestObjectPayload =
    '\n' +
    '  {\n' +
    '    "kid" : "did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0#key-1",\n' +
    '    "typ" : "JWT",\n' +
    '    "alg" : "EdDSA"\n' +
    '  }.\n' +
    '  {\n' +
    '    "response_type" : "id_token",\n' +
    '    "nonce" : "40252afc-6a82-4a2e-905f-e41f122ef575",\n' +
    '    "client_id" : "did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0",\n' +
    '    "response_mode" : "post",\n' +
    '    "nbf" : 1674772063,\n' +
    '    "scope" : "openid",\n' +
    '    "claims" : {\n' +
    '      "vp_token" : {\n' +
      // TODO we need the dcql query
    // '        "presentation_definition" : {\n' +
    // '          "input_descriptors" : [ {\n' +
    // '            "schema" : [ {\n' +
    // '              "uri" : "VerifiedEmployee"\n' +
    // '            } ],\n' +
    // '            "purpose" : "We need to verify that you have a valid VerifiedEmployee Verifiable Credential.",\n' +
    // '            "name" : "VerifiedEmployeeVC",\n' +
    // '            "id" : "VerifiedEmployeeVC"\n' +
    // '          } ],\n' +
    // '          "id" : "649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9"\n' +
    // '        }\n' +
    '      }\n' +
    '    },\n' +
    '    "registration" : {\n' +
    '      "logo_uri" : "https://example.com/verifier-icon.png",\n' +
    '      "tos_uri" : "https://example.com/verifier-info",\n' +
    '      "client_name" : "Example Verifier",\n' +
    '      "vp_formats" : {\n' +
    '        "jwt_vc" : {\n' +
    '          "alg" : [ "EdDSA", "ES256K" ]\n' +
    '        },\n' +
    '        "jwt_vp" : {\n' +
    '          "alg" : [ "EdDSA", "ES256K" ]\n' +
    '        }\n' +
    '      },\n' +
    '      "subject_syntax_types_supported" : [ "did:ion" ]\n' +
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
      'eyJraWQiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJzdWIiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCIsImF1ZCI6ImRpZDppb246RWlCV2U5UnRIVDdWWi1KdWZmOE9ubkpBeUZKdENva2NZSHgxQ1FrRnRwbDdwdzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtOZlQxVktlRWcyYVVsalF6WllaRTVvTjBwdFF5MVVTRmhCVm1GWWJuWjFPVTlGUlZvNGRIRTVUa2tpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5ZVGtKcVNXWk1WR1pPVjBOSE1GUTJNMlZhWW1KRVpGWm9TbUpVVGpndFNtWmxhVXg0ZFcxb1pXNTNJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQ1pWWjVSWEJEYjBOUGVYSjZWRGhEU0hsdlFXMWFjVTFDVDFvMFZUWnFjbTFzZFV0MVNqbHhTMHBrWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUW5oa2NIbHlhbWxWU0ZaMWFrTlJXVEJLTWtoQlVGRllabk53V0ZCS1lXbHVWMjFtVjNSTmNGaG5lRkVpZlgwIiwiaXNzIjoiaHR0cHM6XC9cL3NlbGYtaXNzdWVkLm1lXC92Mlwvb3BlbmlkLXZjIiwiZXhwIjoxNjc0Nzg2NDYzLCJpYXQiOjE2NzQ3NzIwNjMsIm5vbmNlIjoiNDAyNTJhZmMtNmE4Mi00YTJlLTkwNWYtZTQxZjEyMmVmNTc1IiwianRpIjoiMGY1ZGFmZWQtMGQ4Mi00M2IxLWFmNzktNDA0NDBlM2YxMzY2IiwiX3ZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoiOWFmMjRlOGEtYzhmMy00YjlhLTkxNjEtYjcxNWU3N2E2MDEwIiwiZGVmaW5pdGlvbl9pZCI6IjY0OWQ4YzNjLWY1YWMtNDFiZC05YzE5LTU4MDRlYTFiOGZlOSIsImRlc2NyaXB0b3JfbWFwIjpbeyJpZCI6IlZlcmlmaWVkRW1wbG95ZWVWQyIsImZvcm1hdCI6Imp3dF92cCIsInBhdGgiOiIkIiwicGF0aF9uZXN0ZWQiOnsiaWQiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJmb3JtYXQiOiJqd3RfdmMiLCJwYXRoIjoiJC52ZXJpZmlhYmxlQ3JlZGVudGlhbFswXSJ9fV19fX0.jh-SnpQcYPGEb_N5mqKUKCi9pA2OqxXw7BbAYuQwQat69KqpHA0sEZ1tOTOwsVP9UCfjmVg_8z0I_TvKkEkCBA',
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
