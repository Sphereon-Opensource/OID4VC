import { SigningAlgo } from '@sphereon/oid4vc-common'
import { PEX } from '@sphereon/pex'
import { PresentationDefinitionV2 } from '@sphereon/pex-models'
import { OriginalVerifiableCredential } from '@sphereon/ssi-types'

import {
  OP,
  PassBy,
  PresentationDefinitionWithLocation,
  PresentationExchange,
  PresentationVerificationCallback,
  PropertyTarget,
  ResponseIss,
  ResponseType,
  RevocationVerification,
  RP,
  Scope,
  SubjectType,
  SupportedVersion,
  VPTokenLocation,
} from '..'

import { getVerifyJwtCallback, internalSignature } from './DidJwtTestUtils'
import { getResolver } from './ResolverTestUtils'
import { mockedGetEnterpriseAuthToken, pexHasher, sdJwtVcPresentationSignCallback, WELL_KNOWN_OPENID_FEDERATION } from './TestUtils'

jest.setTimeout(30000)

const EXAMPLE_REDIRECT_URL = 'https://acme.com/hello'

const HOLDER_DID = 'did:example:ebfeb1f712ebc6f1c276e12ec21'

const mdocBase64UrlUniversity =
  'uQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xhNgYWGikaGRpZ2VzdElEAHFlbGVtZW50SWRlbnRpZmllcmp1bml2ZXJzaXR5bGVsZW1lbnRWYWx1ZWlpbm5zYnJ1Y2tmcmFuZG9tWCDPDfrRde4BPN5uQhSGnm8zmhFiMm2pjTzx5z3JmEKLKdgYWGOkaGRpZ2VzdElEAXFlbGVtZW50SWRlbnRpZmllcmZkZWdyZWVsZWxlbWVudFZhbHVlaGJhY2hlbG9yZnJhbmRvbVggOUutjAeZTM2jcre7I4Gfeqy81azrsSXtbpWH65QmJTbYGFhhpGhkaWdlc3RJRAJxZWxlbWVudElkZW50aWZpZXJkbmFtZWxlbGVtZW50VmFsdWVoSm9obiBEb2VmcmFuZG9tWCD3XuNqynfdWeNM9qanYauAk5iin3lXV4eCd4RqNaCVBdgYWGGkaGRpZ2VzdElEA3FlbGVtZW50SWRlbnRpZmllcmNub3RsZWxlbWVudFZhbHVlaWRpc2Nsb3NlZGZyYW5kb21YICmBo2MFCt3SoUx36ZNOSPXRcA5hb1ABmy5Q5F9V6_ulamlzc3VlckF1dGiEQ6EBJqIEWDF6RG5hZXJDa3ppOERHNTZRVWN0aTJaSk1jd2ZFcFpLb2VYNW4xRlp3THZjQWZ2VHZpGCGBWPwwgfkwgaCgAwIBAgIQElXcBkTBG_kaIWLYwVbnAzAKBggqhkjOPQQDAjANMQswCQYDVQQGEwJERTAeFw0yNDEwMzAxMTAwMThaFw0yNTEwMzAxMTAwMThaMA0xCzAJBgNVBAYTAkRFMDkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDIgADfu2vJOiV-lZLsM5p3CGYjMXX_hjj9LsQybiK0c9ixVujAjAAMAoGCCqGSM49BAMCA0gAMEUCIQDVhXXnyqyJ7Y8VECpvP4sZ1jTbnQ684CmFAUR2kHuArAIgAhDDybZ9k_sAFpArd9YAlfSBgA6r2SgmhXyxfYdQ26pZAd3YGFkB2LkABmd2ZXJzaW9uYzEuMG9kaWdlc3RBbGdvcml0aG1nU0hBLTI1Nmx2YWx1ZURpZ2VzdHOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xpABYIHxEA-V6vOFCQAuHYIYARAxRgZ_5DgIUy-i9SL_1AMRiAVggcm01ODxrEhO8x6ZsfdhiiZd-e8Qvww0z-C_jlm-rCoICWCAuLB7-RZv_qA5elyMAWDQZUTQXpR20Y-HyHOel7EsCxgNYIJE9tUTIRvZt8NJSmI4-j0NzqKUtt2DBYQZ9CpoC8o64bWRldmljZUtleUluZm-5AAFpZGV2aWNlS2V5pAECIAEhWCB1WBBG2WGAzEWzM4UUUpcGFiJxtCI6sRp_o0SaMJhnNSJYIDDCu4r2F0N8khrP-Hww23HaQTW4X_-bXYwMED_orB7UZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsdmFsaWRpdHlJbmZvuQAEZnNpZ25lZMB0MjAyNC0xMC0zMFQxMTowMDoyMFppdmFsaWRGcm9twHQyMDI0LTEwLTMwVDExOjAwOjIwWmp2YWxpZFVudGlswHQyMDI1LTEwLTMwVDExOjAwOjIwWm5leHBlY3RlZFVwZGF0ZfdYQNiBC_noBzIuL0HdBNCe5GWNKQ07GbRc1Kn0yQ2NE4qY6PbPzd3O4UAaTpeqHclMbHOoAJssSAbxIEooKan-vXI'
const mdocBase64UrlUniversityPresentation =
  'uQADZ3ZlcnNpb25jMS4waWRvY3VtZW50c4GjZ2RvY1R5cGVxb3JnLmV1LnVuaXZlcnNpdHlsaXNzdWVyU2lnbmVkuQACam5hbWVTcGFjZXOhd2V1LmV1cm9wYS5lYy5ldWRpLnBpZC4xgtgYWGGkaGRpZ2VzdElEAnFlbGVtZW50SWRlbnRpZmllcmRuYW1lbGVsZW1lbnRWYWx1ZWhKb2huIERvZWZyYW5kb21YICTUPEzNlBwbcWWOXijZrs4Ed37zoxDCKJYvv0qKtpuv2BhYY6RoZGlnZXN0SUQBcWVsZW1lbnRJZGVudGlmaWVyZmRlZ3JlZWxlbGVtZW50VmFsdWVoYmFjaGVsb3JmcmFuZG9tWCC6uRVoNoBBcj5b-IEDTCUFoNEGVGsMSZP-3YuMUVCKrGppc3N1ZXJBdXRohEOhASaiBFgxekRuYWV0bk5naHRrNHk1VzFDNGpBM3E4VmRYbzhlUzNpWWViRm5MR3I3ZlhTYVVUNhghgVj8MIH5MIGgoAMCAQICEF36OiPSysIvMaLWuTCava8wCgYIKoZIzj0EAwIwDTELMAkGA1UEBhMCREUwHhcNMjQxMDMwMTI1ODQ0WhcNMjUxMDMwMTI1ODQ0WjANMQswCQYDVQQGEwJERTA5MBMGByqGSM49AgEGCCqGSM49AwEHAyIAA6VBlDzOG438-hsPWMSY56vJWrz8m5OaIimg0rG0vY6towIwADAKBggqhkjOPQQDAgNIADBFAiBc_30LjkQFX9YxWUyYH5jFK4Smw2h4KKYU85BBH2xDTAIhAKqb7RwT5_qoVJNYcom0x3N1eVd49TuPZfkbNaZsmhi5WQHd2BhZAdi5AAZndmVyc2lvbmMxLjBvZGlnZXN0QWxnb3JpdGhtZ1NIQS0yNTZsdmFsdWVEaWdlc3RzoXdldS5ldXJvcGEuZWMuZXVkaS5waWQuMaQAWCDrF96Sw8aHk1fZ8B92ZQE7I37MHjVSDoEq4MGhHuMIcwFYIAEsfqF7G_6k-lw2NKPRwHlWSalgrYsbXdcqz1ghPa-nAlggGq9DTWd1xmO8O84B0PCKhtf0daiT34V4xkU-wSGHYUwDWCDX5TNczi_TZSwmJ1VVeEzXpKXR9eweibocvAfpmKHEU21kZXZpY2VLZXlJbmZvuQABaWRldmljZUtleaQBAiABIVggN4_nyaOESmuHV8xhsUl2VqxaF83kIraAc2GV7M2-BKEiWCC0GqqvYnJ6U12ccZVDAOH8CeNGs9oOAF46jXJfauTSO2dkb2NUeXBlcW9yZy5ldS51bml2ZXJzaXR5bHZhbGlkaXR5SW5mb7kABGZzaWduZWTAdDIwMjQtMTAtMzBUMTI6NTg6NDRaaXZhbGlkRnJvbcB0MjAyNC0xMC0zMFQxMjo1ODo0NFpqdmFsaWRVbnRpbMB0MjAyNS0xMC0zMFQxMjo1ODo0NFpuZXhwZWN0ZWRVcGRhdGX3WEC3VoysIcxum_HtX5OCFEA3BwzhHcYmESJDzY58vz0Ez7Zo3fmP3D0M8evzMk7_Cz7_hwVL8sdLgiKpho5UXrunbGRldmljZVNpZ25lZLkAAmpuYW1lU3BhY2Vz2BhDuQAAamRldmljZUF1dGi5AAJvZGV2aWNlU2lnbmF0dXJlhEOhASag91hA9peGbzwyivN7UXvk4smItYMdt-RvcU87ZvXdDfRqIQsWSxGLcke2lHcit77fIEAw_8w0MOzM7ObQWK3T4vTMl2lkZXZpY2VNYWP3ZnN0YXR1cwA'

const sdJwt =
  'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFZERTQSIsImtpZCI6IiN6Nk1rcnpRUEJyNHB5cUM3NzZLS3RyejEzU2NoTTVlUFBic3N1UHVRWmI1dDR1S1EifQ.eyJ2Y3QiOiJPcGVuQmFkZ2VDcmVkZW50aWFsIiwiZGVncmVlIjoiYmFjaGVsb3IiLCJjbmYiOnsia2lkIjoiZGlkOmtleTp6Nk1rcEdSNGdzNFJjM1pwaDR2ajh3Um5qbkF4Z0FQU3hjUjhNQVZLdXRXc3BRemMjejZNa3BHUjRnczRSYzNacGg0dmo4d1Juam5BeGdBUFN4Y1I4TUFWS3V0V3NwUXpjIn0sImlzcyI6ImRpZDprZXk6ejZNa3J6UVBCcjRweXFDNzc2S0t0cnoxM1NjaE01ZVBQYnNzdVB1UVpiNXQ0dUtRIiwiaWF0IjoxNzMwMjkzMTIzLCJfc2QiOlsiVEtuSUJwVGp3ZmpVdFZra3ZBUWNrSDZxSEZFbmFsb1ZtZUF6UmlzZlNNNCIsInRLTFAxWFM3Vm55YkJET2ZWV3hTMVliNU5TTjhlMVBDMHFqRnBnbjd5XzgiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.GhgxbTA_cLZ6-enpOrTRqhIoZEzJoJMSQeutQdhcIayhiem9yd8i0x-h6NhQbN1NrNPwi-JQhy5lpNopVia_AA~WyI3NDU5ODc1MjgyODgyMTY5MjY3NTk1MTgiLCJ1bml2ZXJzaXR5IiwiaW5uc2JydWNrIl0~'

function getPresentationDefinitionV2(withSdJwtInputDescriptor = false): PresentationDefinitionV2 {
  const pd: PresentationDefinitionV2 = {
    id: 'mDL-sample-req',
    input_descriptors: [
      {
        id: 'org.eu.university',
        format: {
          mso_mdoc: {
            alg: ['ES256', 'ES384', 'ES512', 'EdDSA', 'ESB256', 'ESB320', 'ESB384', 'ESB512'],
          },
        },
        constraints: {
          fields: [
            {
              path: ["$['eu.europa.ec.eudi.pid.1']['name']"],
              intent_to_retain: false,
            },
            {
              path: ["$['eu.europa.ec.eudi.pid.1']['degree']"],
              intent_to_retain: false,
            },
          ],
          limit_disclosure: 'required',
        },
      },
    ],
  }

  if (withSdJwtInputDescriptor) {
    pd.input_descriptors.push({
      id: 'OpenBadgeCredentialDescriptor',
      format: {
        'vc+sd-jwt': {
          'sd-jwt_alg_values': ['EdDSA'],
        },
      },
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            path: ['$.vct'],
            filter: {
              type: 'string',
              const: 'OpenBadgeCredential',
            },
          },
          {
            path: ['$.university'],
          },
        ],
      },
    })
  }

  return pd
}

function getVCs(): OriginalVerifiableCredential[] {
  return [sdJwt, mdocBase64UrlUniversity]
}

describe('mdoc RP and OP interaction should', () => {
  it('succeed when calling with presentation definitions and right verifiable presentation without id token', async () => {
    const opMockEntity = await mockedGetEnterpriseAuthToken('OP')
    const rpMockEntity = await mockedGetEnterpriseAuthToken('RP')

    const presentationVerificationCallback: PresentationVerificationCallback = async (presentation) => {
      // higher level library needs to implement actual verification
      return { verified: presentation === mdocBase64UrlUniversityPresentation }
    }

    const resolver = getResolver('ethr')
    const rp = RP.builder({
      requestVersion: SupportedVersion.SIOPv2_D12_OID4VP_D18,
    })
      .withClientId(rpMockEntity.did)
      .withHasher(pexHasher)
      .withResponseType([ResponseType.VP_TOKEN])
      .withRedirectUri(EXAMPLE_REDIRECT_URL)
      .withPresentationDefinition({ definition: getPresentationDefinitionV2() }, [
        PropertyTarget.REQUEST_OBJECT,
        PropertyTarget.AUTHORIZATION_REQUEST,
      ])
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
        responseTypesSupported: [ResponseType.VP_TOKEN],
        vpFormatsSupported: { jwt_vc: { alg: [SigningAlgo.EDDSA] } },
        subjectTypesSupported: [SubjectType.PAIRWISE],
        subject_syntax_types_supported: ['did', 'did:key'],
        passBy: PassBy.VALUE,
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
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
      })
      .withSupportedVersions(SupportedVersion.SIOPv2_ID1)
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

    if (!parsedAuthReqURI.requestObjectJwt) throw new Error('requestObjectJwt is undefined')
    const verifiedAuthReqWithJWT = await op.verifyAuthorizationRequest(parsedAuthReqURI.requestObjectJwt)
    expect(verifiedAuthReqWithJWT.issuer).toMatch(rpMockEntity.did)
    const pex = new PresentationExchange({
      allDIDs: [HOLDER_DID],
      allVerifiableCredentials: getVCs(),
      hasher: pexHasher,
    })
    const pd: PresentationDefinitionWithLocation[] = await PresentationExchange.findValidPresentationDefinitions(
      parsedAuthReqURI.authorizationRequestPayload,
    )
    const results = await pex.selectVerifiableCredentialsForSubmission(pd[0].definition)
    expect(results).toEqual({
      errors: [],
      matches: [
        {
          name: 'org.eu.university',
          rule: 'all',
          vc_path: ['$.verifiableCredential[0]'],
          type: 'InputDescriptor',
          id: 'org.eu.university',
        },
      ],
      areRequiredCredentialsPresent: 'info',
      verifiableCredential: [mdocBase64UrlUniversity],
      warnings: [],
      vcIndexes: [1],
    })

    // NOTE: for now we don't support creating mdoc presentations yes, so we mock that part.
    // Will be added in a follow up PR (need to extend PEX first)
    const presentationResult = new PEX().evaluatePresentation(pd[0].definition, mdocBase64UrlUniversityPresentation, {
      generatePresentationSubmission: true,
    })
    expect(presentationResult).toEqual({
      areRequiredCredentialsPresent: 'info',
      errors: [],
      presentations: [mdocBase64UrlUniversityPresentation],
      value: {
        definition_id: 'mDL-sample-req',
        descriptor_map: [
          {
            format: 'mso_mdoc',
            id: 'org.eu.university',
            path: '$',
          },
        ],
        id: expect.any(String),
      },
      warnings: [],
    })

    const authenticationResponseWithJWT = await op.createAuthorizationResponse(verifiedAuthReqWithJWT, {
      jwtIssuer: {
        method: 'did',
        alg: SigningAlgo.ES256K,
        didUrl: `${rpMockEntity.did}#controller`,
      },
      presentationExchange: {
        verifiablePresentations: [mdocBase64UrlUniversityPresentation],
        vpTokenLocation: VPTokenLocation.AUTHORIZATION_RESPONSE,
        presentationSubmission: presentationResult.value,
      },
    })
    expect(authenticationResponseWithJWT.response.payload).toBeDefined()
    expect(authenticationResponseWithJWT.response.idToken).toBeUndefined()

    const verifiedAuthResponseWithJWT = await rp.verifyAuthorizationResponse(authenticationResponseWithJWT.response.payload, {
      presentationDefinitions: [{ definition: pd[0].definition, location: pd[0].location }],
    })

    // Cannot extract nonce, should be handled by the verification callback that verifies
    // session transcript, until device response parsing is fixed
    expect(verifiedAuthResponseWithJWT.oid4vpSubmission?.nonce).toEqual(undefined)
    expect(verifiedAuthResponseWithJWT.idToken).toBeUndefined()
  })
})
