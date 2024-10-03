import { SigningAlgo } from '@sphereon/oid4vc-common'
import { IProofType } from '@sphereon/ssi-types'

import {
  CreateAuthorizationRequestOpts,
  PassBy,
  PropertyTarget,
  ResponseMode,
  ResponseType,
  RP,
  Scope,
  SubjectIdentifierType,
  SubjectType,
  SupportedVersion,
} from '..'

import { getCreateJwtCallback, getVerifyJwtCallback, internalSignature } from './DidJwtTestUtils'
import { getResolver } from './ResolverTestUtils'
import { WELL_KNOWN_OPENID_FEDERATION } from './TestUtils'
import {
  VERIFIER_LOGO_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT,
  VERIFIER_NAME_FOR_CLIENT_NL,
  VERIFIERZ_PURPOSE_TO_VERIFY,
  VERIFIERZ_PURPOSE_TO_VERIFY_NL,
} from './data/mockedData'

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello'
const EXAMPLE_REFERENCE_URL = 'https://rp.acme.com/siop/jwts'
const EXAMPLE_RESPONSE_REDIRECT_URL = 'https://acme.com/:correlation_id?state=:state'
const HEX_KEY = 'f857544a9d1097e242ff0b287a7e6e90f19cf973efe2317f2a4678739664420f'
const DID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0'
const KID = 'did:ethr:0x0106a2e985b1E1De9B5ddb4aF6dC9e928F4e99D0#keys-1'

const alltargets = [PropertyTarget.AUTHORIZATION_REQUEST, PropertyTarget.REQUEST_OBJECT]

describe('RP OPBuilder should', () => {
  /*it('throw Error when no arguments are passed', async () => {
    expect.assertions(1);
    await expect(() => new OPBuilder().build()).toThrowError(Error);
  });*/

  it('build an RP when all arguments are set', async () => {
    expect.assertions(1)

    const resolver = getResolver('ethr')
    expect(
      RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
        .withClientId('test_client_id')
        .withScope('test')
        .withResponseType(ResponseType.ID_TOKEN)
        .withVerifyJwtCallback(getVerifyJwtCallback(resolver))
        .withRedirectUri('https://redirect.me')
        .withRequestBy(PassBy.VALUE)
        .withResponseMode(ResponseMode.POST)
        .withClientMetadata({
          passBy: PassBy.REFERENCE,
          reference_uri: 'https://registration.here',
          logo_uri: VERIFIER_LOGO_FOR_CLIENT,
          clientName: VERIFIER_NAME_FOR_CLIENT,
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '2022100339',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
        })

        .withCreateJwtCallback(internalSignature('myprivatekye', 'did:example:123', 'did:example:123#key', SigningAlgo.ES256K))
        .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
        .build(),
    ).toBeInstanceOf(RP)
  })
})

describe('RP should', () => {
  it('throw Error when build from request opts without enough params', async () => {
    expect.assertions(1)
    await expect(() => RP.fromRequestOpts({} as never)).toThrowError(Error)
  })
  it('return an RP when all request arguments are set', async () => {
    expect.assertions(1)

    const opts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: 'test',
        scope: 'test',
        response_type: 'test',
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        jwtIssuer: {
          method: 'did',
          didUrl: KID,
          alg: SigningAlgo.ES256K,
        },
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,
        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
          alg: SigningAlgo.ES256K,
        }),
      },
      clientMetadata: {
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
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + '202210040',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY,
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL,
      },
    }

    expect(RP.fromRequestOpts(opts)).toBeInstanceOf(RP)
  })

  it('succeed from request opts when all params are set', async () => {
    // expect.assertions(1);
    const opts: CreateAuthorizationRequestOpts = {
      version: SupportedVersion.SIOPv2_ID1,
      payload: {
        client_id: WELL_KNOWN_OPENID_FEDERATION,
        scope: 'openid',
        response_type: 'id_token',
        response_mode: ResponseMode.POST,
        redirect_uri: EXAMPLE_REDIRECT_URL,
      },
      requestObject: {
        jwtIssuer: {
          method: 'did',
          didUrl: KID,
          alg: SigningAlgo.ES256K,
        },
        passBy: PassBy.REFERENCE,
        reference_uri: EXAMPLE_REFERENCE_URL,

        createJwtCallback: getCreateJwtCallback({
          hexPrivateKey: HEX_KEY,
          did: DID,
          kid: KID,
          alg: SigningAlgo.ES256K,
        }),
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
          ldp_vc: { proof_type: [IProofType.EcdsaSecp256k1Signature2019, IProofType.EcdsaSecp256k1Signature2019] },
        },
        passBy: PassBy.VALUE,
        logo_uri: VERIFIER_LOGO_FOR_CLIENT + ' 2022-09-29 00',
        clientName: VERIFIER_NAME_FOR_CLIENT + ' 2022-09-29 00',
        'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + ' 2022-09-29 00',
        clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY + ' 2022-09-29 00',
        'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL + ' 2022-09-29 00',
      },
    }

    const expectedPayloadWithoutRequest = {
      response_type: 'id_token',
      scope: 'openid',
      client_id: WELL_KNOWN_OPENID_FEDERATION,
      redirect_uri: 'https://acme.com/hello',
      // nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      /* registration: {
        id_token_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        response_types_supported: [ResponseType.ID_TOKEN],
        scopes_supported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr', 'did'],
        subject_types_supported: [SubjectType.PAIRWISE],
        vp_formats: {
          jwt: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
          jwt_vc: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
        },
        logo_uri: VERIFIER_LOGO_FOR_CLIENT + ' 2022-09-29 00',
        client_name: VERIFIER_NAME_FOR_CLIENT + ' 2022-09-29 00',
        'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + ' 2022-09-29 00',
        client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY + ' 2022-09-29 00',
        'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL + ' 2022-09-29 00',
      },*/
    }

    const expectedUri =
      'openid4vp://?client_id=https%3A%2F%2Fwww.example.com%2F.well-known%2Fopenid-federation&scope=openid&response_type=id_token&response_mode=post&redirect_uri=https%3A%2F%2Facme.com%2Fhello&request_uri=https%3A%2F%2Frp.acme.com%2Fsiop%2Fjwts'
    const expectedJwtRegex =
      /^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDAxMDZhMmU5ODViMUUxRGU5QjVkZGI0YUY2ZEM5ZTkyOEY0ZTk5RDAja2V5cy0xIiwidHlwIjoiSldUIn0\.ey.*$/

    const request = await RP.fromRequestOpts(opts).createAuthorizationRequestURI({
      correlationId: '1234',
      state: 'b32f0087fc9816eb813fd11f',
      nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
    })
    expect(request.authorizationRequestPayload).toMatchObject(expectedPayloadWithoutRequest)
    expect(request.encodedUri).toMatch(expectedUri)
    expect(request.requestObjectJwt).toMatch(expectedJwtRegex)
  })

  it('succeed from builder when all params are set', async () => {
    const expectedPayloadWithoutRequest = {
      client_id: WELL_KNOWN_OPENID_FEDERATION,
      // nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
      redirect_uri: 'https://acme.com/hello',
      registration: {
        id_token_signing_alg_values_supported: [SigningAlgo.EDDSA],
        request_object_signing_alg_values_supported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
        response_types_supported: [ResponseType.ID_TOKEN],
        scopes_supported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
        subject_syntax_types_supported: ['did:ethr'],
        subject_types_supported: [SubjectType.PAIRWISE],
        vp_formats: {
          jwt: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
          jwt_vc: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
          jwt_vp: {
            alg: ['EdDSA', 'ES256K', 'ES256'],
          },
        },
        logo_uri: VERIFIER_LOGO_FOR_CLIENT + ' 2022-09-29 01',
        client_name: VERIFIER_NAME_FOR_CLIENT + ' 2022-09-29 01',
        'client_name#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + ' 2022-09-29 01',
        client_purpose: VERIFIERZ_PURPOSE_TO_VERIFY + ' 2022-09-29 01',
        'client_purpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL + ' 2022-09-29 01',
      },
    }

    const expectedUri =
      'openid4vp://?client_id=https%3A%2F%2Fwww.example.com%2F.well-known%2Fopenid-federation&scope=test&response_type=id_token&redirect_uri=https%3A%2F%2Facme.com%2Fhello&registration=%7B%22id_token_signing_alg_values_supported%22%3A%5B%22EdDSA%22%5D%2C%22request_object_signing_alg_values_supported%22%3A%5B%22EdDSA%22%2C%22ES256%22%5D%2C%22response_types_supported%22%3A%5B%22id_token%22%5D%2C%22scopes_supported%22%3A%5B%22openid%20did_authn%22%2C%22openid%22%5D%2C%22subject_types_supported%22%3A%5B%22pairwise%22%5D%2C%22subject_syntax_types_supported%22%3A%5B%22did%3Aethr%22%5D%2C%22vp_formats%22%3A%7B%22jwt%22%3A%7B%22alg%22%3A%5B%22EdDSA%22%2C%22ES256K%22%2C%22ES256%22%5D%7D%2C%22jwt_vc%22%3A%7B%22alg%22%3A%5B%22EdDSA%22%2C%22ES256K%22%2C%22ES256%22%5D%7D%2C%22jwt_vp%22%3A%7B%22alg%22%3A%5B%22EdDSA%22%2C%22ES256K%22%2C%22ES256%22%5D%7D%7D%2C%22client_name%22%3A%22Client%20Verifier%20Relying%20Party%20Sphereon%20INC%202022-09-29%2001%22%2C%22logo_uri%22%3A%22https%3A%2F%2Fsphereon.com%2Fcontent%2Fthemes%2Fsphereon%2Fassets%2Ffavicons%2Fsafari-pinned-tab.svg%202022-09-29%2001%22%2C%22client_purpose%22%3A%22To%20request%2C%20receive%20and%20verify%20your%20credential%20about%20the%20the%20valid%20subject.%202022-09-29%2001%22%2C%22client_id%22%3A%22https%3A%2F%2Fwww.example.com%2F.well-known%2Fopenid-federation%22%2C%22client_name%23nl-NL%22%3A%22%20***%20dutch%20***%20Client%20Verifier%20Relying%20Party%20Sphereon%20B.V.%202022-09-29%2001%22%2C%22client_purpose%23nl-NL%22%3A%22%20***%20Dutch%20***%20To%20request%2C%20receive%20and%20verify%20your%20credential%20about%20the%20the%20valid%20subject.%202022-09-29%2001%22%7D&request_uri=https%3A%2F%2Frp.acme.com%2Fsiop%2Fjwts'

    const expectedJwtRegex =
      /^eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXRocjoweDAxMDZhMmU5ODViMUUxRGU5QjVkZGI0YUY2ZEM5ZTkyOEY0ZTk5RDAja2V5cy0xIiwidHlwIjoiSldUIn0\.eyJpYXQiO.*$/

    const rp = RP.builder({ requestVersion: SupportedVersion.SIOPv2_ID1 })
      .withClientId(WELL_KNOWN_OPENID_FEDERATION, alltargets)
      .withScope('test', alltargets)
      .withResponseType(ResponseType.ID_TOKEN, alltargets)
      .withVerifyJwtCallback(getVerifyJwtCallback(getResolver('ethr')))
      .withRedirectUri(EXAMPLE_REDIRECT_URL, alltargets)
      .withResponseRedirectUri(EXAMPLE_RESPONSE_REDIRECT_URL)
      .withRequestBy(PassBy.REFERENCE, EXAMPLE_REFERENCE_URL)
      .withCreateJwtCallback(internalSignature(HEX_KEY, DID, KID, SigningAlgo.ES256K))
      .withClientMetadata(
        {
          client_id: WELL_KNOWN_OPENID_FEDERATION,
          idTokenSigningAlgValuesSupported: [SigningAlgo.EDDSA],
          requestObjectSigningAlgValuesSupported: [SigningAlgo.EDDSA, SigningAlgo.ES256],
          responseTypesSupported: [ResponseType.ID_TOKEN],
          vpFormatsSupported: {
            jwt: {
              alg: ['EdDSA', 'ES256K', 'ES256'],
            },
            jwt_vc: {
              alg: ['EdDSA', 'ES256K', 'ES256'],
            },
            jwt_vp: {
              alg: ['EdDSA', 'ES256K', 'ES256'],
            },
          },
          scopesSupported: [Scope.OPENID_DIDAUTHN, Scope.OPENID],
          subjectTypesSupported: [SubjectType.PAIRWISE],
          subject_syntax_types_supported: ['did:ethr'],
          passBy: PassBy.VALUE,
          logo_uri: VERIFIER_LOGO_FOR_CLIENT + ' 2022-09-29 01',
          clientName: VERIFIER_NAME_FOR_CLIENT + ' 2022-09-29 01',
          'clientName#nl-NL': VERIFIER_NAME_FOR_CLIENT_NL + ' 2022-09-29 01',
          clientPurpose: VERIFIERZ_PURPOSE_TO_VERIFY + ' 2022-09-29 01',
          'clientPurpose#nl-NL': VERIFIERZ_PURPOSE_TO_VERIFY_NL + ' 2022-09-29 01',
        },
        alltargets,
      )
      .withSupportedVersions([SupportedVersion.SIOPv2_D11])
      .build()
    const request = await rp.createAuthorizationRequestURI({
        correlationId: '1234',
        state: 'b32f0087fc9816eb813fd11f',
        nonce: 'qBrR7mqnY3Qr49dAZycPF8FzgE83m6H0c2l0bzP4xSg',
        jwtIssuer: { method: 'did', didUrl: KID, alg: SigningAlgo.ES256K },
      })
    expect(request.authorizationRequestPayload).toMatchObject(expectedPayloadWithoutRequest)
    expect(request.encodedUri).toMatch(expectedUri)
    expect(request.requestObjectJwt).toMatch(expectedJwtRegex)
    
    const responseRedirectUri = rp.getResponseRedirectUri({correlation_id: '1234', state: 'b32f0087fc9816eb813fd11f'})
    expect(responseRedirectUri).toBe('https://acme.com/1234?state=b32f0087fc9816eb813fd11f')
  })
})
