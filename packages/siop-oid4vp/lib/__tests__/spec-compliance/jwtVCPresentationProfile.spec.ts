import { PresentationSignCallBackParams } from '@sphereon/pex'
import { IProofType } from '@sphereon/ssi-types'
import * as jose from 'jose'
import { KeyLike } from 'jose'
import nock from 'nock'
import * as u8a from 'uint8arrays'

import {
  AuthorizationRequest,
  AuthorizationResponse,
  IDToken,
  OP,
  PassBy,
  PresentationDefinitionLocation,
  PresentationExchange,
  PresentationSignCallback,
  PresentationVerificationCallback,
  PropertyTarget,
  ResponseMode,
  ResponseType,
  RevocationVerification,
  RP,
  SigningAlgo,
  SupportedVersion,
  VPTokenLocation,
} from '../..'
import { getVerifyJwtCallback, internalSignature } from '../DidJwtTestUtils'
import { getResolver } from '../ResolverTestUtils'

let rp: RP
let op: OP

afterEach(() => {
  nock.cleanAll()
})

const presentationVerificationCallback: PresentationVerificationCallback = async () => ({ verified: true })
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const presentationSignCallback: PresentationSignCallback = async (_args: PresentationSignCallBackParams) =>
  TestVectors.authorizationResponsePayload.vp_token

const verifyJwtCallback = getVerifyJwtCallback(getResolver('ion'), {
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
        // targets: [PropertyTarget.REQUEST_OBJECT],
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
        subject_syntax_types_supported: ['did:ion'],
      },
      PropertyTarget.REQUEST_OBJECT,
    )
    .withRedirectUri('https://example.com/siop-response', PropertyTarget.REQUEST_OBJECT)
    .withRequestBy(PassBy.REFERENCE, TestVectors.request_uri)
    .withCreateJwtCallback(internalSignature(TestVectors.verifierHexPrivateKey, TestVectors.verifierDID, TestVectors.verifierKID, SigningAlgo.EDDSA))
    .withVerifyJwtCallback(verifyJwtCallback)
    .build()

  op = OP.builder()
    .withCreateJwtCallback(internalSignature(TestVectors.holderHexPrivateKey, TestVectors.holderDID, TestVectors.holderKID, SigningAlgo.EDDSA))
    .withVerifyJwtCallback(verifyJwtCallback)
    .addSupportedVersion(SupportedVersion.JWT_VC_PRESENTATION_PROFILE_v1)
    .build()
})

describe('RP using test vectors', () => {
  it('should create matching auth request and URI', async () => {
    const authRequest = await createAuthRequest()
    expect(await authRequest.requestObject?.getPayload()).toMatchObject({
      response_type: 'id_token',
      nonce: '40252afc-6a82-4a2e-905f-e41f122ef575',
      client_id:
        'did:ion:EiBAA99TAezxKRc2wuuBnr4zzGsS2YcsOA4IPQV0KY64Xg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkdnWkdUZzhlQ2E3bFYyOE1MOUpUbUJVdms3RFlCYmZSS1dMaHc2NUpvMXMiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaURKV0Z2WUJ5Qzd2azA2MXAzdHYwd29WSTk5MTFQTGgwUVp4cWpZM2Y4MVFRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlBX1RvVlNBZDBTRWxOU2VrQ1k1UDVHZ01KQy1MTVpFY2ZSV2ZqZGNaYXJFQSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpRDN0ZTV4eFliemJod0pYdEUwZ2tZV3Z3MlZ2VFB4MU9la0RTcXduZzRTWmcifX0',
      response_mode: 'post',
      // "nbf" : 1674772063,
      scope: 'openid',
      claims: {
        vp_token: {
          presentation_definition: {
            input_descriptors: [
              {
                schema: [
                  {
                    uri: 'VerifiedEmployee',
                  },
                ],
                purpose: 'We need to verify that you have a valid VerifiedEmployee Verifiable Credential.',
                name: 'VerifiedEmployeeVC',
                id: 'VerifiedEmployeeVC',
              },
            ],
            id: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
          },
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
      'openid-vc://?request_uri=https%3A%2F%2Fexample%2Fservice%2Fapi%2Fv1%2Fpresentation-request%2F649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
    )
  })
  it('should get presentation definition', async () => {
    const authRequest = await createAuthRequest()
    const defs = await authRequest.getPresentationDefinitions()
    expect(defs).toBeDefined()
    expect(defs).toHaveLength(1)
  })
  it('should decode id token jwt', async () => {
    const idToken = await IDToken.fromIDToken(TestVectors.idTokenJwt)
    expect(idToken).toBeDefined()
    const payload = await idToken.payload()
    expect(payload).toEqual(TestVectors.idTokenPayload)
    expect(
      await idToken.verify({
        correlationId: '1234',
        audience:
          'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0',
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
    expect(await authorizationResponse.idToken?.payload()).toEqual(TestVectors.idTokenPayload)
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
    const presentationDefinitions = await authRequest.getPresentationDefinitions()

    const verified = await authorizationResponse.verify({
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
      presentationDefinitions,
    })
    expect(verified).toBeDefined()
  })
})

describe('OP using test vectors', () => {
  it('should import auth request and be able to provide the auth request unaltered', async () => {
    nock('https://example').get('/service/api/v1/presentation-request/649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9').reply(200, TestVectors.requestObjectJwt)
    // expect.assertions(1);
    const result = await op.verifyAuthorizationRequest(TestVectors.auth_request, {
      verification: {},
    })
    expect(result).toBeDefined()
  })

  it('should use test vector auth response', async () => {
    const authorizationResponse = await AuthorizationResponse.fromPayload(TestVectors.authorizationResponsePayload)

    expect(authorizationResponse.payload.vp_token).toBeDefined()
    expect(authorizationResponse.payload.id_token).toBeDefined()
    expect(await authorizationResponse.idToken?.payload()).toEqual({
      _vp_token: {
        presentation_submission: {
          definition_id: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
          descriptor_map: [
            {
              format: 'jwt_vp',
              id: 'VerifiedEmployeeVC',
              path: '$',
              path_nested: {
                format: 'jwt_vc',
                id: 'VerifiedEmployeeVC',
                path: '$.verifiableCredential[0]',
              },
            },
          ],
          id: '9af24e8a-c8f3-4b9a-9161-b715e77a6010',
        },
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
      presentationDefinitions: [
        {
          definition: TestVectors.presentationDef,
          location: PresentationDefinitionLocation.CLAIMS_VP_TOKEN,
        },
      ],
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
    const presentationExchange = new PresentationExchange({
      allDIDs: [TestVectors.holderDID],
      allVerifiableCredentials: [TestVectors.jwtVCFromVPToken],
    })
    const verifiablePresentationResult = await presentationExchange.createVerifiablePresentation(
      TestVectors.presentationDef,
      [TestVectors.jwtVCFromVPToken],
      presentationSignCallback,
      {
        holderDID: TestVectors.holderDID,
        signatureOptions: {},
        proofOptions: {
          type: IProofType.JwtProof2020,
        },
      },
    )
    await op.createAuthorizationResponse(result, {
      presentationExchange: {
        verifiablePresentations: [verifiablePresentationResult.verifiablePresentation],
        presentationSubmission: TestVectors.presentation_submission,
        vpTokenLocation: VPTokenLocation.ID_TOKEN,
      },
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
          presentation_definition: {
            input_descriptors: [
              {
                schema: [
                  {
                    uri: 'VerifiedEmployee',
                  },
                ],
                purpose: 'We need to verify that you have a valid VerifiedEmployee Verifiable Credential.',
                name: 'VerifiedEmployeeVC',
                id: 'VerifiedEmployeeVC',
              },
            ],
            id: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
          },
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
  public static issuerKey
  public static issuerPrivateKey
  public static issuerPublicKey
  public static issuerHexPrivateKey

  public static holderJwk = {
    kty: 'OKP',
    d: 'ZeDOVmemqzPAK0R2F1BHVfRYC7g65p_UpyXhEaX03N4',
    crv: 'Ed25519',
    kid: 'key-1',
    x: 'w06OV7e6nTurt6G9VpVXxIwYnyjfupxeGyKBS-blqvg',
  }
  public static holderDID =
    'did:ion:EiAeM6No9kdpos6_ehBUDh4RINY4USDMh-QdWksmsI3WkA:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IncwNk9WN2U2blR1cnQ2RzlWcFZYeEl3WW55amZ1cHhlR3lLQlMtYmxxdmciLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUFSNGRVQmxqNWNGa3dMdkpTWUYzVExjLV81MWhDX2xZaGxXZkxWZ29seTRRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlEcVJyWU5fV3JTakFQdnlFYlJQRVk4WVhPRmNvT0RTZExUTWItM2FKVElGQSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQUwyMFdYakpQQW54WWdQY1U5RV9POE1OdHNpQk00QktpaVNwT3ZFTWpVOUEifX0'
  public static holderKID = `${TestVectors.holderDID}#key-1`
  public static holderKey
  public static holderPrivateKey
  public static holderPublicKey
  public static holderHexPrivateKey

  public static verifierJwk = {
    kty: 'OKP',
    d: 'SP18SnbU9f-Rph0GwulyvmLFyCXDHqZVKWDo2E41llQ',
    crv: 'Ed25519',
    kid: 'key-1',
    x: 'C_OUJxH6iIcC6XdNh7JmC-THXAVaXnvu9OEEZ8tq9NI',
  }
  public static verifierDID =
    'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0'

  public static verifierKID = `${TestVectors.verifierDID}#key-1`
  public static verifierKey: jose.KeyLike | Uint8Array
  public static verifierPrivateKey: string
  public static verifierPublicKey: string
  public static verifierHexPrivateKey: string

  public static async init() {
    TestVectors.issuerKey = (await jose.importJWK(TestVectors.issuerJwk, 'EdDSA', true)) as KeyLike
    TestVectors.issuerPrivateKey = u8a.toString(u8a.fromString(TestVectors.issuerJwk.d, 'base64url'), 'hex')
    TestVectors.issuerPublicKey = u8a.toString(u8a.fromString(TestVectors.issuerJwk.x, 'base64url'), 'hex')
    TestVectors.issuerHexPrivateKey = `${TestVectors.issuerPrivateKey}${TestVectors.issuerPublicKey}`

    TestVectors.holderKey = (await jose.importJWK(TestVectors.holderJwk, 'EdDSA', true)) as KeyLike
    TestVectors.holderPrivateKey = u8a.toString(u8a.fromString(TestVectors.holderJwk.d, 'base64url'), 'hex')
    TestVectors.holderPublicKey = u8a.toString(u8a.fromString(TestVectors.holderJwk.x, 'base64url'), 'hex')
    TestVectors.holderHexPrivateKey = `${TestVectors.holderPrivateKey}${TestVectors.holderPublicKey}`

    TestVectors.verifierKey = (await jose.importJWK(TestVectors.verifierJwk, 'EdDSA', true)) as KeyLike
    TestVectors.verifierPrivateKey = u8a.toString(u8a.fromString(TestVectors.verifierJwk.d, 'base64url'), 'hex')
    TestVectors.verifierPublicKey = u8a.toString(u8a.fromString(TestVectors.verifierJwk.x, 'base64url'), 'hex')
    TestVectors.verifierHexPrivateKey = `${TestVectors.verifierPrivateKey}${TestVectors.verifierPublicKey}`
  }

  public static auth_request = 'openid-vc://?request_uri=https://example/service/api/v1/presentation-request/649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9'
  public static request_uri = 'https://example/service/api/v1/presentation-request/649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9'

  public static idTokenJwt =
    'eyJraWQiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCNrZXktMSIsImFsZyI6IkVkRFNBIn0.eyJzdWIiOiJkaWQ6aW9uOkVpQWVNNk5vOWtkcG9zNl9laEJVRGg0UklOWTRVU0RNaC1RZFdrc21zSTNXa0E6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNkluY3dOazlXTjJVMmJsUjFjblEyUnpsV2NGWlllRWwzV1c1NWFtWjFjSGhsUjNsTFFsTXRZbXh4ZG1jaUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVGU05HUlZRbXhxTldOR2EzZE1ka3BUV1VZelZFeGpMVjgxTVdoRFgyeFphR3hYWmt4V1oyOXNlVFJSSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbEVjVkp5V1U1ZlYzSlRha0ZRZG5sRllsSlFSVms0V1ZoUFJtTnZUMFJUWkV4VVRXSXRNMkZLVkVsR1FTSXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFVd3lNRmRZYWtwUVFXNTRXV2RRWTFVNVJWOVBPRTFPZEhOcFFrMDBRa3RwYVZOd1QzWkZUV3BWT1VFaWZYMCIsImF1ZCI6ImRpZDppb246RWlCV2U5UnRIVDdWWi1KdWZmOE9ubkpBeUZKdENva2NZSHgxQ1FrRnRwbDdwdzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtOZlQxVktlRWcyYVVsalF6WllaRTVvTjBwdFF5MVVTRmhCVm1GWWJuWjFPVTlGUlZvNGRIRTVUa2tpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5ZVGtKcVNXWk1WR1pPVjBOSE1GUTJNMlZhWW1KRVpGWm9TbUpVVGpndFNtWmxhVXg0ZFcxb1pXNTNJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQ1pWWjVSWEJEYjBOUGVYSjZWRGhEU0hsdlFXMWFjVTFDVDFvMFZUWnFjbTFzZFV0MVNqbHhTMHBrWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUW5oa2NIbHlhbWxWU0ZaMWFrTlJXVEJLTWtoQlVGRllabk53V0ZCS1lXbHVWMjFtVjNSTmNGaG5lRkVpZlgwIiwiaXNzIjoiaHR0cHM6XC9cL3NlbGYtaXNzdWVkLm1lXC92Mlwvb3BlbmlkLXZjIiwiZXhwIjoxNjc0Nzg2NDYzLCJpYXQiOjE2NzQ3NzIwNjMsIm5vbmNlIjoiNDAyNTJhZmMtNmE4Mi00YTJlLTkwNWYtZTQxZjEyMmVmNTc1IiwianRpIjoiMGY1ZGFmZWQtMGQ4Mi00M2IxLWFmNzktNDA0NDBlM2YxMzY2IiwiX3ZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9zdWJtaXNzaW9uIjp7ImlkIjoiOWFmMjRlOGEtYzhmMy00YjlhLTkxNjEtYjcxNWU3N2E2MDEwIiwiZGVmaW5pdGlvbl9pZCI6IjY0OWQ4YzNjLWY1YWMtNDFiZC05YzE5LTU4MDRlYTFiOGZlOSIsImRlc2NyaXB0b3JfbWFwIjpbeyJpZCI6IlZlcmlmaWVkRW1wbG95ZWVWQyIsImZvcm1hdCI6Imp3dF92cCIsInBhdGgiOiIkIiwicGF0aF9uZXN0ZWQiOnsiaWQiOiJWZXJpZmllZEVtcGxveWVlVkMiLCJmb3JtYXQiOiJqd3RfdmMiLCJwYXRoIjoiJC52ZXJpZmlhYmxlQ3JlZGVudGlhbFswXSJ9fV19fX0.jh-SnpQcYPGEb_N5mqKUKCi9pA2OqxXw7BbAYuQwQat69KqpHA0sEZ1tOTOwsVP9UCfjmVg_8z0I_TvKkEkCBA'

  public static presentation_submission = {
    descriptor_map: [
      {
        path: '$',
        format: 'jwt_vp',
        path_nested: {
          path: '$.verifiableCredential[0]',
          format: 'jwt_vc',
          id: 'VerifiedEmployeeVC',
        },
        id: 'VerifiedEmployeeVC',
      },
    ],
    definition_id: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
    id: '9af24e8a-c8f3-4b9a-9161-b715e77a6010',
  }

  public static idTokenPayload = {
    sub: 'did:ion:EiAeM6No9kdpos6_ehBUDh4RINY4USDMh-QdWksmsI3WkA:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IncwNk9WN2U2blR1cnQ2RzlWcFZYeEl3WW55amZ1cHhlR3lLQlMtYmxxdmciLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUFSNGRVQmxqNWNGa3dMdkpTWUYzVExjLV81MWhDX2xZaGxXZkxWZ29seTRRIn0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlEcVJyWU5fV3JTakFQdnlFYlJQRVk4WVhPRmNvT0RTZExUTWItM2FKVElGQSIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQUwyMFdYakpQQW54WWdQY1U5RV9POE1OdHNpQk00QktpaVNwT3ZFTWpVOUEifX0',
    aud: 'did:ion:EiBWe9RtHT7VZ-Juff8OnnJAyFJtCokcYHx1CQkFtpl7pw:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJrZXktMSIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJFZDI1NTE5Iiwia3R5IjoiT0tQIiwieCI6IkNfT1VKeEg2aUljQzZYZE5oN0ptQy1USFhBVmFYbnZ1OU9FRVo4dHE5TkkiLCJraWQiOiJrZXktMSJ9LCJwdXJwb3NlcyI6WyJhdXRoZW50aWNhdGlvbiJdLCJ0eXBlIjoiSnNvbldlYktleTIwMjAifV19fV0sInVwZGF0ZUNvbW1pdG1lbnQiOiJFaUNYTkJqSWZMVGZOV0NHMFQ2M2VaYmJEZFZoSmJUTjgtSmZlaUx4dW1oZW53In0sInN1ZmZpeERhdGEiOnsiZGVsdGFIYXNoIjoiRWlCZVZ5RXBDb0NPeXJ6VDhDSHlvQW1acU1CT1o0VTZqcm1sdUt1SjlxS0pkZyIsInJlY292ZXJ5Q29tbWl0bWVudCI6IkVpQnhkcHlyamlVSFZ1akNRWTBKMkhBUFFYZnNwWFBKYWluV21mV3RNcFhneFEifX0',
    iss: 'https://self-issued.me/v2/openid-vc',
    exp: 1674786463,
    iat: 1674772063,
    nonce: '40252afc-6a82-4a2e-905f-e41f122ef575',
    jti: '0f5dafed-0d82-43b1-af79-40440e3f1366',
    _vp_token: {
      presentation_submission: {
        descriptor_map: [
          {
            path: '$',
            format: 'jwt_vp',
            path_nested: {
              path: '$.verifiableCredential[0]',
              format: 'jwt_vc',
              id: 'VerifiedEmployeeVC',
            },
            id: 'VerifiedEmployeeVC',
          },
        ],
        definition_id: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
        id: '9af24e8a-c8f3-4b9a-9161-b715e77a6010',
      },
    },
  }
  public static presentationDef = {
    input_descriptors: [
      {
        schema: [
          {
            uri: 'VerifiedEmployee',
          },
        ],
        purpose: 'We need to verify that you have a valid VerifiedEmployee Verifiable Credential.',
        name: 'VerifiedEmployeeVC',
        id: 'VerifiedEmployeeVC',
      },
    ],
    id: '649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9',
  }

  public static requestObjectJwt =
    'eyJraWQiOiJkaWQ6aW9uOkVpQldlOVJ0SFQ3VlotSnVmZjhPbm5KQXlGSnRDb2tjWUh4MUNRa0Z0cGw3cHc6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKclpYa3RNU0lzSW5CMVlteHBZMHRsZVVwM2F5STZleUpqY25ZaU9pSkZaREkxTlRFNUlpd2lhM1I1SWpvaVQwdFFJaXdpZUNJNklrTmZUMVZLZUVnMmFVbGpRelpZWkU1b04wcHRReTFVU0ZoQlZtRllibloxT1U5RlJWbzRkSEU1VGtraUxDSnJhV1FpT2lKclpYa3RNU0o5TENKd2RYSndiM05sY3lJNld5SmhkWFJvWlc1MGFXTmhkR2x2YmlKZExDSjBlWEJsSWpvaVNuTnZibGRsWWt0bGVUSXdNakFpZlYxOWZWMHNJblZ3WkdGMFpVTnZiVzFwZEcxbGJuUWlPaUpGYVVOWVRrSnFTV1pNVkdaT1YwTkhNRlEyTTJWYVltSkVaRlpvU21KVVRqZ3RTbVpsYVV4NGRXMW9aVzUzSW4wc0luTjFabVpwZUVSaGRHRWlPbnNpWkdWc2RHRklZWE5vSWpvaVJXbENaVlo1UlhCRGIwTlBlWEo2VkRoRFNIbHZRVzFhY1UxQ1QxbzBWVFpxY20xc2RVdDFTamx4UzBwa1p5SXNJbkpsWTI5MlpYSjVRMjl0YldsMGJXVnVkQ0k2SWtWcFFuaGtjSGx5YW1sVlNGWjFha05SV1RCS01raEJVRkZZWm5Od1dGQktZV2x1VjIxbVYzUk5jRmhuZUZFaWZYMCNrZXktMSIsInR5cCI6IkpXVCIsImFsZyI6IkVkRFNBIn0.eyJyZXNwb25zZV90eXBlIjoiaWRfdG9rZW4iLCJub25jZSI6IjQwMjUyYWZjLTZhODItNGEyZS05MDVmLWU0MWYxMjJlZjU3NSIsImNsaWVudF9pZCI6ImRpZDppb246RWlCV2U5UnRIVDdWWi1KdWZmOE9ubkpBeUZKdENva2NZSHgxQ1FrRnRwbDdwdzpleUprWld4MFlTSTZleUp3WVhSamFHVnpJanBiZXlKaFkzUnBiMjRpT2lKeVpYQnNZV05sSWl3aVpHOWpkVzFsYm5RaU9uc2ljSFZpYkdsalMyVjVjeUk2VzNzaWFXUWlPaUpyWlhrdE1TSXNJbkIxWW14cFkwdGxlVXAzYXlJNmV5SmpjbllpT2lKRlpESTFOVEU1SWl3aWEzUjVJam9pVDB0UUlpd2llQ0k2SWtOZlQxVktlRWcyYVVsalF6WllaRTVvTjBwdFF5MVVTRmhCVm1GWWJuWjFPVTlGUlZvNGRIRTVUa2tpTENKcmFXUWlPaUpyWlhrdE1TSjlMQ0p3ZFhKd2IzTmxjeUk2V3lKaGRYUm9aVzUwYVdOaGRHbHZiaUpkTENKMGVYQmxJam9pU25OdmJsZGxZa3RsZVRJd01qQWlmVjE5ZlYwc0luVndaR0YwWlVOdmJXMXBkRzFsYm5RaU9pSkZhVU5ZVGtKcVNXWk1WR1pPVjBOSE1GUTJNMlZhWW1KRVpGWm9TbUpVVGpndFNtWmxhVXg0ZFcxb1pXNTNJbjBzSW5OMVptWnBlRVJoZEdFaU9uc2laR1ZzZEdGSVlYTm9Jam9pUldsQ1pWWjVSWEJEYjBOUGVYSjZWRGhEU0hsdlFXMWFjVTFDVDFvMFZUWnFjbTFzZFV0MVNqbHhTMHBrWnlJc0luSmxZMjkyWlhKNVEyOXRiV2wwYldWdWRDSTZJa1ZwUW5oa2NIbHlhbWxWU0ZaMWFrTlJXVEJLTWtoQlVGRllabk53V0ZCS1lXbHVWMjFtVjNSTmNGaG5lRkVpZlgwIiwicmVzcG9uc2VfbW9kZSI6InBvc3QiLCJuYmYiOjE2NzQ3NzIwNjMsInNjb3BlIjoib3BlbmlkIiwiY2xhaW1zIjp7InZwX3Rva2VuIjp7InByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiNjQ5ZDhjM2MtZjVhYy00MWJkLTljMTktNTgwNGVhMWI4ZmU5IiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiVmVyaWZpZWRFbXBsb3llZVZDIiwibmFtZSI6IlZlcmlmaWVkRW1wbG95ZWVWQyIsInB1cnBvc2UiOiJXZSBuZWVkIHRvIHZlcmlmeSB0aGF0IHlvdSBoYXZlIGEgVmVyaWZpZWRFbXBsb3llZSBWZXJpZmlhYmxlIENyZWRlbnRpYWwuIiwic2NoZW1hIjpbeyJ1cmkiOiJWZXJpZmllZEVtcGxveWVlIn1dfV19fX0sInJlZ2lzdHJhdGlvbiI6eyJjbGllbnRfbmFtZSI6IkV4YW1wbGUgVmVyaWZpZXIiLCJ0b3NfdXJpIjoiaHR0cHM6XC9cL2V4YW1wbGUuY29tXC92ZXJpZmllci1pbmZvIiwibG9nb191cmkiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL3ZlcmlmaWVyLWljb24ucG5nIiwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbImRpZDppb24iXSwidnBfZm9ybWF0cyI6eyJqd3RfdnAiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTZLIl19LCJqd3RfdmMiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTZLIl19fX0sInN0YXRlIjoiNjQ5ZDhjM2MtZjVhYy00MWJkLTljMTktNTgwNGVhMWI4ZmU5IiwicmVkaXJlY3RfdXJpIjoiaHR0cHM6XC9cL2V4YW1wbGUuY29tXC9zaW9wLXJlc3BvbnNlIiwiZXhwIjoxNjc0Nzc1NjYzLCJpYXQiOjE2NzQ3NzIwNjMsImp0aSI6ImYwZTZkY2Y1LTNmZTYtNDUwNy1hZGM5LWI0OTZkYWYzNDUxMiJ9.znX9h8l8JYoy8BHlnZzRDBEpaAv3hkb_XfUEzG-9eZID3tJjJdrO7PAr4kTay-nxvMhkzNsQg1rCZsjOMbKbBg'
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
    '        "presentation_definition" : {\n' +
    '          "input_descriptors" : [ {\n' +
    '            "schema" : [ {\n' +
    '              "uri" : "VerifiedEmployee"\n' +
    '            } ],\n' +
    '            "purpose" : "We need to verify that you have a valid VerifiedEmployee Verifiable Credential.",\n' +
    '            "name" : "VerifiedEmployeeVC",\n' +
    '            "id" : "VerifiedEmployeeVC"\n' +
    '          } ],\n' +
    '          "id" : "649d8c3c-f5ac-41bd-9c19-5804ea1b8fe9"\n' +
    '        }\n' +
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
