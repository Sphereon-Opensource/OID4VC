import { SigningAlgo } from '@sphereon/oid4vc-common'
import { IProofType } from '@sphereon/ssi-types'
import nock from 'nock'
import { describe, expect, it } from 'vitest'

import {
  AuthorizationResponseOpts,
  CreateAuthorizationRequestOpts,
  OP,
  PassBy,
  ResponseIss,
  ResponseMode,
  ResponseType,
  RP,
  Scope,
  SubjectIdentifierType,
  SubjectType,
  SupportedVersion,
  VerifyAuthorizationRequestOpts,
} from '..'

import { getCreateJwtCallback, getVerifyJwtCallback, internalSignature } from './DidJwtTestUtils'
import { getResolver } from './ResolverTestUtils'
import { mockedGetEnterpriseAuthToken, WELL_KNOWN_OPENID_FEDERATION } from './TestUtils'
import {
  UNIT_TEST_TIMEOUT,
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData'

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello'
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts'

const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f'
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0'
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#controller'

describe('OP OPBuilder should', () => {
  /*it('throw Error when no arguments are passed', async () => {
    expect.assertions(1);
    await expect(() => new OPBuilder().build()).toThrowError(Error);
  });*/
  it('build an OP when all arguments are set', async () => {
    expect.assertions(1)

    expect(
      OP.builder()
        .withIssuer(ResponseIss.SELF_ISSUED_V2)
        .withResponseMode(ResponseMode.POST)
        .withRegistration({
          passBy: PassBy.REFERENCE,
          reference_uri: 'https://registration.here',
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100332',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .withCreateJwtCallback(internalSignature('myprivatekey', 'did:example:123', 'did:example:123#key', SigningAlgo.ES256K))
        .withVerifyJwtCallback(getVerifyJwtCallback(getResolver('ethr'), { checkLinkedDomain: 'never' }))
        .withExpiresIn(1000)
        .withSupportedVersions([SupportedVersion.SIOPv2_ID1])
        .build(),
    ).toBeInstanceOf(OP)
  })
})

describe('OP should', () => {
  const responseOpts: AuthorizationResponseOpts = {
    responseURI: EXAMPLE_REDIRECT_URL,
    responseURIType: 'redirect_uri',
    createJwtCallback: getCreateJwtCallback({
      hexPrivateKey: HEX_KEY,
      did: DID,
      kid: KID,
      alg: SigningAlgo.ES256K,
    }),
    jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
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
    expiresIn: 2000,
  }

  const resolver = getResolver('ethr')
  const verifyOpts: VerifyAuthorizationRequestOpts = {
    verifyJwtCallback: getVerifyJwtCallback(resolver),
    verification: {},
    correlationId: '1234',
    supportedVersions: [SupportedVersion.SIOPv2_ID1],
    nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
  }

  /*it('throw Error when build from request opts without enough params', async () => {
    expect.assertions(1);
    await expect(() => OP.fromOpts({} as never, {} as never)).toThrowError(Error);
  });*/

  it('return an OP when all request arguments are set', async () => {
    expect.assertions(1)

    expect(OP.fromOpts(responseOpts, verifyOpts)).toBeInstanceOf(OP)
  })

  it(
    'succeed from request opts when all params are set',
    async () => {
      const mockEntity = await mockedGetEnterpriseAuthToken('ACME Corp')
      const requestOpts: CreateAuthorizationRequestOpts = {
        version: SupportedVersion.SIOPv2_ID1,

        requestObject: {
          jwtIssuer: {
            method: 'did',
            didUrl: `${mockEntity.did}#controller`,
            alg: SigningAlgo.ES256K,
            options: {
              kid: '1234',
            },
          },
          passBy: PassBy.REFERENCE,
          reference_uri: EXAMPLE_REFERENCE_URL,

          createJwtCallback: getCreateJwtCallback({
            hexPrivateKey: mockEntity.hexPrivateKey,
            did: mockEntity.did,
            kid: `${mockEntity.did}#controller`,
            alg: SigningAlgo.ES256K,
          }),
          payload: {
            redirect_uri: EXAMPLE_REDIRECT_URL,
            client_id: WELL_KNOWN_OPENID_FEDERATION,
            scope: 'test',
            response_type: 'id_token',
          },
        },
        clientMetadata: {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          subject_syntax_types_supported: ['did:ethr', SubjectIdentifierType.DID],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          vpFormatsSupported: {
            jwt_vc: { alg: [SigningAlgo.EDDSA, SigningAlgo.ES256K, SigningAlgo.ES256] },
            jwt_vp: { alg: [SigningAlgo.EDDSA, SigningAlgo.ES256K, SigningAlgo.ES256] },
            jwt: { alg: [SigningAlgo.EDDSA, SigningAlgo.ES256K, SigningAlgo.ES256] },
          },
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100334',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        },
      }

      const requestURI = await RP.fromRequestOpts(requestOpts).createAuthorizationRequestURI({
        correlationId: '1234',
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
        state: 'b32f0087fc9816eb813fd11f',
        jwtIssuer: { method: 'did', didUrl: `${mockEntity.did}#controller`, alg: SigningAlgo.ES256K, options: { kid: '1234' } },
      })

      nock('https://rp.acme.com').get('/siop/jwts').reply(200, requestURI.requestObjectJwt)
      try {
        const verifiedRequest = await OP.fromOpts(responseOpts, verifyOpts).verifyAuthorizationRequest(requestURI.encodedUri)
        // console.log(JSON.stringify(verifiedRequest));
        expect(verifiedRequest.issuer).toMatch(mockEntity.did)
        expect(verifiedRequest.jwt).toBeDefined()
      } catch (e) {
        if (e.message.includes('Service Unavailable')) {
          console.warn('Temporarily skipped due to Service Unavailable')
        } else {
          throw e
        }
      }
    },
    UNIT_TEST_TIMEOUT,
  )

  it('succeed from builder when all params are set', async () => {
    try {
      const rpMockEntity = await mockedGetEnterpriseAuthToken('ACME RP')
      const opMockEntity = await mockedGetEnterpriseAuthToken('ACME OP')

      const requestURI = await RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
        .withClientId(WELL_KNOWN_OPENID_FEDERATION)
        .withScope('test')
        .withResponseType(ResponseType.ID_TOKEN)
        .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
        .withRedirectUri(EXAMPLE_REFERENCE_URL)
        .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
        .withRequestBy(PassBy.VALUE)
        .withCreateJwtCallback(
          getCreateJwtCallback({
            hexPrivateKey: rpMockEntity.hexPrivateKey,
            did: rpMockEntity.did,
            kid: `${rpMockEntity.did}#controller`,
            alg: SigningAlgo.ES256K,
          }),
        )
        .withClientMetadata({
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did', 'did:ethr'],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100335',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .build()

        .createAuthorizationRequestURI({
          correlationId: '1234',
          nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
          state: 'b32f0087fc9816eb813fd11f',
          jwtIssuer: { method: 'did', didUrl: `${rpMockEntity.did}#controller`, alg: SigningAlgo.ES256K },
        })

      const verifiedRequest = await OP.builder()
        .withSupportedVersions([SupportedVersion.SIOPv2_ID1])
        .withExpiresIn(1000)
        .withIssuer(ResponseIss.SELF_ISSUED_V2)
        .withVerifyJwtCallback(getVerifyJwtCallback(resolver, { checkLinkedDomain: 'never' }))
        .withCreateJwtCallback(
          getCreateJwtCallback({
            hexPrivateKey: opMockEntity.hexPrivateKey,
            did: opMockEntity.did,
            kid: `${opMockEntity.did}#controller`,
            alg: SigningAlgo.ES256K,
          }),
        )
        .withRegistration({
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormats: { ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] } },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did', 'did:ethr'],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100336',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })
        .build()

        .verifyAuthorizationRequest(requestURI.encodedUri)
      // console.log(JSON.stringify(verifiedRequest));
      expect(verifiedRequest.issuer).toMatch(rpMockEntity.did)
      expect(verifiedRequest.jwt).toBeDefined()
    } catch (e) {
      if (e.message.includes('Service Unavailable')) {
        console.warn('Temporarily skipped due to Service Unavailable')
      } else {
        throw e
      }
    }
  })
})
