// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import nock from 'nock'
import { describe, expect, it } from 'vitest'

import { AuthorizationResponseOpts, OP, SupportedVersion, VerifyAuthorizationRequestOpts } from '../../../'
import { getVerifyJwtCallback } from '../../DidJwtTestUtils'
import { getResolver } from '../../ResolverTestUtils'
import { UNIT_TEST_TIMEOUT } from '../../data/mockedData'

const SIOP_URI =
  'openid://?state=3f3a673a-7835-42f1-a03e-b186fd042dcc&client_id=https%3A%2F%2Fconformance-test.ebsi.eu%2Fconformance%2Fv3%2Fauth-mock&redirect_uri=https%3A%2F%2Fconformance-test.ebsi.eu%2Fconformance%2Fv3%2Fauth-mock%2Fdirect_post&response_type=id_token&response_mode=direct_post&scope=openid&nonce=3a50effa-4505-42ce-8708-0c4ab32378dd&request_uri=https%3A%2F%2Fconformance-test.ebsi.eu%2Fconformance%2Fv3%2Fauth-mock%2Frequest_uri%2F4cb2dc1f-61a4-46b7-9660-06d62dd99700'
const JWT =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkZMeEkzTE04bUZDRkNEMUg0VmpacVd0MVBmaWQyaThBQ1lpRHZFelo5VU0ifQ.eyJzdGF0ZSI6IjNmM2E2NzNhLTc4MzUtNDJmMS1hMDNlLWIxODZmZDA0MmRjYyIsImNsaWVudF9pZCI6Imh0dHBzOi8vY29uZm9ybWFuY2UtdGVzdC5lYnNpLmV1L2NvbmZvcm1hbmNlL3YzL2F1dGgtbW9jayIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vY29uZm9ybWFuY2UtdGVzdC5lYnNpLmV1L2NvbmZvcm1hbmNlL3YzL2F1dGgtbW9jay9kaXJlY3RfcG9zdCIsInJlc3BvbnNlX3R5cGUiOiJpZF90b2tlbiIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsInNjb3BlIjoib3BlbmlkIiwibm9uY2UiOiIzYTUwZWZmYS00NTA1LTQyY2UtODcwOC0wYzRhYjMyMzc4ZGQiLCJpc3MiOiJodHRwczovL2NvbmZvcm1hbmNlLXRlc3QuZWJzaS5ldS9jb25mb3JtYW5jZS92My9hdXRoLW1vY2siLCJhdWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnFTWlpGakc0dFZnS2hFd0twcm9qcUxCM0MyWXBqNEg3M1N0Z2pNa1NYZzJtUXh1V0xmenVSMTJRc052Z1FXenJ6S1NmN1lSQk5yUlhLNzF2ZnExMkJieXhUTEZFWkJXZm5IcWV6QlZHUWlOTGZxZXV5d1pIZ3N0TUNjUzQ0VFhmYjIifQ.h0nQfHq2sck4PizIleqlTTPPjYPgEH8OPKK0ug7r_O7N4qEghfILnL07cs5y1gARIH7hJLNNvI7qXEerl-SdDw'
describe('EBSI', () => {
  const responseOpts: AuthorizationResponseOpts = {
    createJwtCallback: () => {
      throw new Error('Not implemented')
    },
    /*checkLinkedDomain: CheckLinkedDomain.NEVER,
    responseURI: EXAMPLE_REDIRECT_URL,
    responseURIType: 'redirect_uri',
    signature: {
      hexPrivateKey: HEX_KEY,
      did: DID,
      kid: KID,
      alg: SigningAlgo.ES256K,
    },
    registration: {
      authorizationEndpoint: 'www.myauthorizationendpoint.com',
      responseTypesSupported: [ResponseType.ID_TOKEN],
      subject_syntax_types_supported: ['did:web'],
      vpFormats: {
        ldp_vc: {
          proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019],
        },
      },
      logo_uri: VERIFIER_LOGO_FOR_CLIENT,
      clientName: VERIFIER_NAME_FOR_CLIENT,
      'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100333',
      clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
      'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      //TODO: fill it up with actual value
      issuer: ResponseIss.SELF_ISSUED_V2,
      passBy: PassBy.VALUE,
    },
    responseMode: ResponseMode.POST,
    expiresIn: 2000,*/
  }

  const verifyOpts: VerifyAuthorizationRequestOpts = {
    verifyJwtCallback: getVerifyJwtCallback(getResolver('ebsi')),
    verification: {},
    correlationId: '1234',
    supportedVersions: [SupportedVersion.SIOPv2_D12_OID4VP_D18],
  }
  it.skip(
    'succeed from request opts when all params are set',
    async () => {
      nock('https://conformance-test.ebsi.eu/conformance/v3/auth-mock/request_uri/4cb2dc1f-61a4-46b7-9660-06d62dd99700').get('').reply(200, JWT)

      const op = OP.fromOpts(responseOpts, verifyOpts)
      const verifiedRequest = await op.verifyAuthorizationRequest(SIOP_URI)
      expect(verifiedRequest.issuer).toMatch('https://conformance-test.ebsi.eu/conformance/v3/auth-mock')
      expect(verifiedRequest.jwt).toBeDefined()
    },
    UNIT_TEST_TIMEOUT,
  )
})
