import { EventEmitter } from 'events'
import { defaultHasher, SigningAlgo } from '@sphereon/oid4vc-common'
import { CredentialMapper, decodeSdJwtVc } from '@sphereon/ssi-types'
import { DcqlPresentation, DcqlQuery, DcqlQueryResult, DcqlSdJwtVcCredential } from 'dcql'
import { describe, expect, it } from 'vitest'
import {
    hasCryptographicHolderBinding,
    InMemoryRPSessionManager,
    Json,
    OP,
    PassBy,
    PresentationVerificationCallback,
    PropertyTarget,
    ResponseIss,
    ResponseMode,
    ResponseType,
    RevocationVerification,
    RP,
    Scope,
    SubjectType,
    SupportedVersion,
} from '../'
import { getVerifyJwtCallback, internalSignature } from './DidJwtTestUtils'
import { getResolver } from './ResolverTestUtils'
import { mockedGetEnterpriseAuthToken, pexHasher, sdJwtVcPresentationSignCallback, WELL_KNOWN_OPENID_FEDERATION } from './TestUtils'
import {
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData'

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello'

const KB_SD_JWT_PRESENTATION =
    'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6a2V5OnNvbWUtcmFuZG9tLWRpZC1rZXkiLCJpYXQiOjE3MzU4MzY0NzY1NjksInZjdCI6Imh0dHBzOi8vaGlnaC1hc3N1cmFuY2UuY29tL1N0YXRlQnVzaW5lc3NMaWNlbnNlIiwiX3NkIjpbIk5ub3U2OGN6VG9qQWY0Z3dIMmJiNFBaWHB4WHJzQ29oWm5CbEZvQ293TTAiLCJ1ajZZZVZwSnRwUjhVWHRpbmVDOGM5LXpTRFJVQzJzSGhsRkNNNWtkLXlNIl0sIl9zZF9hbGciOiJzaGEtMjU2In0.X1pNBBmR-7h6SgxtmZY9GL_nSBzoIvWNw7nqqgJVCnSEbvyTjqTgu4bLSPKeaxf1jY2zHJK1jdxiDzIizRZ0gA~WyI4OTE4YjkxZGFjMzk1OTdkIiwidXNlciIseyJkYXRlX29mX2JpcnRoIjoiMDEvMDEvMTk3MCIsIl9zZCI6WyJ6UE8zb1RCT3BxMmRNcWQtekt5SmF2UlQyWVIwSHBPaV9jczZRajEtVmR3Il19XQ~WyIyOTc4NTNiODE5MTI0MTJkIiwibmFtZSIsIkpvaG4iXQ~WyJkYjEzNDQ4NTgxMzY0M2JlIiwibGljZW5zZSIseyJfc2QiOlsiWUFUR3A3TGxjNEMtTWtYWkZWTEF6RHRtbDFTMVpFWFFyTW5CdmVDWVFwayJdfV0~WyJlOTc3MzhiNmM0OGNhMWJlIiwibnVtYmVyIiwxMF0~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MzU4MzY0NzYsImF1ZCI6Imh0dHBzOi8vZXhhbXBsZS5jb20iLCJub25jZSI6InFCclI3bXFuWTNRcjQ5ZEFaeWNQRjhGemdFODNtNkgwYzJsMGJ6UDR4U2ciLCJjdXN0b20iOiJkYXRhIiwic2RfaGFzaCI6IlVwYzNYQWpzRU1mdnVmSzJ5Q3RkNDZXUFJmTDVfVDc4UThEZVNZQXlEX28ifQ.Crw56nLFFnVulRQElpq9HoskdKIyd5Mj6vg9UVNSWfhxQ0oGe10RHtifUv4BiFharSvWN99y_DnkhCPu1sPIYw'

const SD_JWT_VC = {
    compactJwtVc: KB_SD_JWT_PRESENTATION,
    decodedPayload: {
        iat: 1700464736076,
        iss: "did:key:some-random-did-key",
        nbf: 1700464736176,
        vct: "https://high-assurance.com/StateBusinessLicense",
        user: {
            dateOfBirth: "20000101",
            lastName: "Doe",
            name: "John"
        },
        license: {
            "number": 10
        },
        cnf: {
            jwk: {
                kty: "EC",
                crv: "P-256",
                x: "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
                y: "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
            }
        }
    }
}

const dcqlQuery = {
  credentials: [
    {
      id: 'my_credential',
      format: 'dc+sd-jwt',
      meta: {
        vct_values: ['https://high-assurance.com/StateBusinessLicense'],
      },
      claims: [{ path: ['license', 'number'] }, { path: ['user', 'name'] }],
      require_cryptographic_holder_binding: false
    },
  ],
} satisfies DcqlQuery.Input

const parsedDcqlQuery = DcqlQuery.parse(dcqlQuery)
DcqlQuery.validate(parsedDcqlQuery)

const dcqlCredential = {
    credential_format: 'dc+sd-jwt',
    vct: SD_JWT_VC.decodedPayload.vct,
    claims: SD_JWT_VC.decodedPayload,
    cryptographic_holder_binding: hasCryptographicHolderBinding('dc+sd-jwt', CredentialMapper.toWrappedVerifiableCredential(decodeSdJwtVc(SD_JWT_VC.compactJwtVc, defaultHasher)))
} satisfies DcqlSdJwtVcCredential

describe.skip('RP and OP interaction should', () => {
  // FIXME SDK-45 Uniresolver failing
  it('succeed when calling with DCQL query and right DCQL presentation', async () => {
    const opMock = await mockedGetEnterpriseAuthToken('OP')
    const opMockEntity = {
      ...opMock,
      didKey: `${opMock.did}#controller`,
    }
    const rpMock = await mockedGetEnterpriseAuthToken('RP')
    const rpMockEntity = {
      ...rpMock,
      didKey: `${rpMock.did}#controller`,
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => {
      return { verified: true }
    }

    const resolver = getResolver('ethr')
    const eventEmitter = new EventEmitter()
    const replayRegistry = new InMemoryRPSessionManager(eventEmitter)
    const rp = RP.builder({ requestVersion: SupportedVersion.OID4VP_v1 })
      .withEventEmitter(eventEmitter)
      .withSessionManager(replayRegistry)
      .withClientId(rpMockEntity.did)
      .withScope('test')
      .withHasher(pexHasher)
      .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withDcqlQuery(parsedDcqlQuery, [PropertyTarget.REQUEST_OBJECT])
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.VALUE)
      .withCreateJwtCallback(internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        response_types_supported: [ResponseType.ID_TOKEN],
        vp_formats_supported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:key'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100322',
        client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.OID4VP_v1)
      .build()

    const op = OP.builder()
      .withPresentationSignCallback(sdJwtVcPresentationSignCallback)
      .withExpiresIn(1000)
      .withHasher(pexHasher)
      .withCreateJwtCallback(internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100323',
        client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.OID4VP_v1)
      .build()

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    })

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri)
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined()
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined()

    if (!parsedAuthReqURI.requestObjectJwt) {
        throw new Error('requestObjectJwt is undefined')
    }
    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt)
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did)

    const dcqlQueryResult: DcqlQueryResult = DcqlQuery.query(parsedDcqlQuery, [dcqlCredential])

    const presentation: DcqlPresentation.Output = {}
    for (const [key, value] of Object.entries(dcqlQueryResult.credential_matches)) {
        if (value.success) {
            presentation[key] = SD_JWT_VC.compactJwtVc
        }
    }

    const dcqlPresentation = DcqlPresentation.parse(presentation)

    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
        dcqlResponse: {
            dcqlPresentation
        }
    })
    expect(authenticationResponseWithJWT.response.payload).toBeDefined()
    expect(authenticationResponseWithJWT.response.idToken).toBeDefined()

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      dcqlQuery: parsedDcqlQuery
    })

    expect(verifiedAuthResponseWithJWT.idToken?.jwt).toBeDefined()
    expect(verifiedAuthResponseWithJWT.idToken?.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg')
  })

  it('succeed when calling with DCQL query and right DCQL presentation without id token', async () => {
    const opMockEntity = await mockedGetEnterpriseAuthToken('OP')
    const rpMockEntity = await mockedGetEnterpriseAuthToken('RP')

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => {
      return { verified: true }
    }

    const resolver = getResolver('ethr')
    const eventEmitter = new EventEmitter()
    const replayRegistry = new InMemoryRPSessionManager(eventEmitter)
    const rp = RP.builder({
      requestVersion: SupportedVersion.OID4VP_v1,
    })
      .withEventEmitter(eventEmitter)
      .withSessionManager(replayRegistry)
      .withClientId(rpMockEntity.did)
      .withHasher(pexHasher)
      .withResponseType([ResponseType.VP_TOKEN])
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withDcqlQuery(parsedDcqlQuery, [PropertyTarget.REQUEST_OBJECT])
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.VALUE)
      .withCreateJwtCallback(internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        response_types_supported: [ResponseType.VP_TOKEN],
        vp_formats_supported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:key'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100322',
        client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.OID4VP_v1)
      .build()

    const op = OP.builder()
      .withPresentationSignCallback(sdJwtVcPresentationSignCallback)
      .withExpiresIn(1000)
      .withHasher(pexHasher)
      .withCreateJwtCallback(internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100323',
        client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.OID4VP_v1)
      .build()

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
      jwtIssuer: { method: 'did', alg: SigningAlgo.ES256K, didUrl: `${rpMockEntity.did}#controller` },
    })

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri)
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined()
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined()

    if (!parsedAuthReqURI.requestObjectJwt) {
        throw new Error('requestObjectJwt is undefined')
    }
    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt)
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did)

    const dcqlQueryResult: DcqlQueryResult = DcqlQuery.query(parsedDcqlQuery, [dcqlCredential])

    const presentation: DcqlPresentation.Output = {}
    for (const [key, value] of Object.entries(dcqlQueryResult.credential_matches)) {
        if (value.success) {
            presentation[key] = SD_JWT_VC.compactJwtVc
        }
    }

    const dcqlPresentation = DcqlPresentation.parse(presentation)

    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      jwtIssuer: {
        method: 'did',
        alg: SigningAlgo.ES256K,
        didUrl: `${rpMockEntity.did}#controller`,
      },
      dcqlResponse: {
          dcqlPresentation
      }
    })
    expect(authenticationResponseWithJWT.response.payload).toBeDefined()
    expect(authenticationResponseWithJWT.response.idToken).toBeUndefined()

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
        dcqlQuery: parsedDcqlQuery
    })

    expect(verifiedAuthResponseWithJWT.oid4vpSubmission?.nonce).toEqual('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg')
    expect(verifiedAuthResponseWithJWT.idToken).toBeUndefined()
  })

  it('succeed when calling with DCQL and right verifiable presentation', async () => {
    const opMock = await mockedGetEnterpriseAuthToken('OP')
    const opMockEntity = {
      ...opMock,
      didKey: `${opMock.did}#controller`,
    }
    const rpMock = await mockedGetEnterpriseAuthToken('RP')
    const rpMockEntity = {
      ...rpMock,
      didKey: `${rpMock.did}#controller`,
    }

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const presentationVerificationCallback: PresentationVerificationCallback = async (_args) => {
      return { verified: true }
    }

    const resolver = getResolver('ethr')
    const eventEmitter = new EventEmitter()
    const replayRegistry = new InMemoryRPSessionManager(eventEmitter)
    const rp = RP.builder({ requestVersion: SupportedVersion.OID4VP_v1 })
      .withEventEmitter(eventEmitter)
      .withSessionManager(replayRegistry)
      .withClientId(rpMockEntity.did)
      .withScope('test')
      .withHasher(pexHasher)
      .withResponseType([ResponseType.ID_TOKEN, ResponseType.VP_TOKEN])
      .withResponseMode(ResponseMode.DIRECT_POST)
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withDcqlQuery(parsedDcqlQuery, [PropertyTarget.REQUEST_OBJECT])
      .withPresentationVerification(presentationVerificationCallback)
      .withRevocationVerification(RevocationVerification.NEVER)
      .withRequestBy(PassBy.VALUE)
      .withCreateJwtCallback(internalSignature(rpMockEntity.hexPrivateKey, rpMockEntity.did, `${rpMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withAuthorizationEndpoint('www.myauthorizationendpoint.com')
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withClientMetadata({
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        response_types_supported: [ResponseType.ID_TOKEN],
        vp_formats_supported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:key'],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100322',
        client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .build()

    const op = OP.builder()
      .withPresentationSignCallback(sdJwtVcPresentationSignCallback)
      .withExpiresIn(1000)
      .withHasher(pexHasher)
      .withCreateJwtCallback(internalSignature(opMockEntity.hexPrivateKey, opMockEntity.did, `${opMockEntity.did}#controller`, SigningAlgo.ES256K))
      .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
      .withRegistration({
        authorizationEndpoint: 'www.myauthorizationendpoint.com',
        idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
        issuer: ResponseIss.SELF_ISSUED_V2,
        requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        responseTypesSupported: [ResponseType.ID_TOKEN, ResponseType.VP_TOKEN],
        vpFormats: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: [],
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT,
        clientName: VERIFIER_NAME_FOR_CLIENT,
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100323',
        client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      })
      .withSupportedVersions(SupportedVersion.OID4VP_v1)
      .build()

    const requestURI = await rp.createAuthorizationRequestURI({
      correlationId: '1234',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      state: 'b32f0087fc9816eb813fd11f',
    })

    // Let's test the parsing
    const parsedAuthReqURI = await op.parseAuthorizationRequestURI(requestURI.encodedUri)
    expect(parsedAuthReqURI.authorizationRequestPayload).toBeDefined()
    expect(parsedAuthReqURI.requestObjectJwt).toBeDefined()

    if (!parsedAuthReqURI.requestObjectJwt) throw new Error('requestObjectJwt is undefined')
    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt)
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did)

    // The KB property is added to the JWT when the presentation is signed. Passing a VC will make the test fail
    const dcqlCredentials = [KB_SD_JWT_PRESENTATION].map((vc) => ({
      credential_format: 'dc+sd-jwt',
      claims: decodeSdJwtVc(vc as string, defaultHasher).decodedPayload as { [x: string]: Json },
      vct: decodeSdJwtVc(vc as string, defaultHasher).decodedPayload.vct,
      cryptographic_holder_binding: true
    })) satisfies DcqlSdJwtVcCredential[]

    const queryResult = DcqlQuery.query(parsedDcqlQuery, dcqlCredentials)

      // TODO
    // expect(queryResult).toEqual({
    //   canBeSatisfied: true,
    //   credential_matches: {
    //     my_credential: {
    //       all: [
    //         [
    //           {
    //             // credential_index: 0,
    //             claim_set_index: undefined,
    //             input_credential_index: 0,
    //             issues: undefined,
    //             output: {
    //               claims: {
    //                 license: {
    //                   number: 10,
    //                 },
    //                 user: {
    //                   name: 'John',
    //                 },
    //               },
    //               credential_format: "dc+sd-jwt",
    //               vct: 'https://high-assurance.com/StateBusinessLicense',
    //             },
    //             success: true,
    //             typed: true,
    //           },
    //         ],
    //       ],
    //       // credential_index: 0,
    //       claim_set_index: undefined,
    //       input_credential_index: 0,
    //       output: {
    //         claims: {
    //           license: {
    //             number: 10,
    //           },
    //           user: {
    //             name: 'John',
    //           },
    //         },
    //         credential_format: "dc+sd-jwt",
    //         vct: 'https://high-assurance.com/StateBusinessLicense',
    //       },
    //       success: true,
    //       typed: true,
    //     },
    //   },
    //   credential_sets: undefined,
    //   credentials: [
    //     {
    //       claims: [
    //         {
    //           path: ['license', 'number'],
    //         },
    //         {
    //           path: ['user', 'name'],
    //         },
    //       ],
    //       format: 'dc+sd-jwt',
    //       id: 'my_credential',
    //       meta: {
    //         vct_values: ['https://high-assurance.com/StateBusinessLicense'],
    //       },
    //     },
    //   ],
    // })

    const dcqlPresentation: { [x: string]: string | { [x: string]: Json } } = {}

    for (const [key, _] of Object.entries(queryResult.credential_matches)) {
      dcqlPresentation[key] = KB_SD_JWT_PRESENTATION as string | { [x: string]: Json }
    }

    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      dcqlResponse: { dcqlPresentation },
    })
    expect(authenticationResponseWithJWT.response.payload).toBeDefined()
    expect(authenticationResponseWithJWT.response.idToken).toBeDefined()

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      dcqlQuery: parsedDcqlQuery,
    })

    expect(verifiedAuthResponseWithJWT.idToken?.jwt).toBeDefined()
    expect(verifiedAuthResponseWithJWT.idToken?.payload.nonce).toMatch('qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg')
  })
})
