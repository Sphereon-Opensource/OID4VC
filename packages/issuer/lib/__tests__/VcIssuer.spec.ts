import { OpenID4VCIClient } from '@sphereon/oid4vci-client'
import {
  Alg,
  AuthzFlowType,
  CredentialFormat,
  CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11,
  CredentialOfferSession,
  CredentialRequest,
  CredentialSupported,
  IssuerCredentialSubjectDisplay,
  STATE_MISSING_ERROR,
} from '@sphereon/oid4vci-common'
import { IProofPurpose, IProofType } from '@sphereon/ssi-types'

import { VcIssuer } from '../VcIssuer'
import { CredentialSupportedBuilderV1_11, VcIssuerBuilder } from '../builder'
import { MemoryStates } from '../state-manager'

const IDENTIPROOF_ISSUER_URL = 'https://issuer.research.identiproof.io'

describe('VcIssuer', () => {
  let vcIssuer: VcIssuer
  const issuerState = 'previously-created-state'
  const clientId = 'sphereon:wallet'
  const preAuthorizedCode = 'test_code'

  beforeAll(async () => {
    const credentialsSupported: CredentialSupported = new CredentialSupportedBuilderV1_11()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      //FIXME Here a CredentialFormatEnum is passed in, but later it is matched against a CredentialFormat
      .withFormat(CredentialFormat.jwt_vc_json)
      .withId('UniversityDegree_JWT')
      .withCredentialDisplay({
        name: 'University Credential',
        locale: 'en-US',
        logo: {
          url: 'https://exampleuniversity.com/public/logo.png',
          alt_text: 'a square logo of a university',
        },
        background_color: '#12107c',
        text_color: '#FFFFFF',
      })
      .withIssuerCredentialSubjectDisplay('given_name', {
        name: 'given name',
        locale: 'en-US',
      } as IssuerCredentialSubjectDisplay)
      .build()
    const stateManager = new MemoryStates<CredentialOfferSession>()
    await stateManager.set('previously-created-state', {
      issuerState,
      clientId,
      preAuthorizedCode,
      createdOn: +new Date(),
      userPin: 123456,
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'did:key:test',
          credential_definition: {
            types: ['VerifiableCredential'],
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            credentialSubject: {},
          },
          grants: {
            authorization_code: { issuer_state: issuerState },
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': preAuthorizedCode,
              user_pin_required: true,
            },
          },
        } as CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11,
      },
    })
    vcIssuer = new VcIssuerBuilder()
      .withAuthorizationServer('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer(IDENTIPROOF_ISSUER_URL)
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withCredentialsSupported(credentialsSupported)
      .withCredentialOfferStateManager(stateManager)
      .withInMemoryCNonceState()
      .withInMemoryCredentialOfferURIState()
      .withIssuerCallback(() =>
        Promise.resolve({
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential'],
          issuer: 'did:key:test',
          issuanceDate: new Date().toISOString(),
          credentialSubject: {},
          proof: {
            type: IProofType.JwtProof2020,
            jwt: 'ye.ye.ye',
            created: new Date().toISOString(),
            proofPurpose: IProofPurpose.assertionMethod,
            verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf',
          },
        })
      )
      .withJWTVerifyCallback(() =>
        Promise.resolve({
          header: {
            typ: 'openid4vci-proof+jwt',
            alg: Alg.ES256K,
            kid: 'test-kid',
          },
          payload: {
            aud: 'https://credential-issuer',
            iat: +new Date(),
            nonce: 'test-nonce',
          },
        })
      )
      .build()
  })

  afterAll(async () => {
    await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  it('should create credential offer', async () => {
    const uri = await vcIssuer.createCredentialOfferURI({
      grants: {
        authorization_code: {
          issuer_state: issuerState,
        },
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthorizedCode,
          user_pin_required: true,
        },
      },
      scheme: 'http',
      baseUri: 'issuer-example.com',
    })
    expect(uri).toEqual(
      'http://issuer-example.com?credential_offer=%7B%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22previously-created-state%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22test_code%22%2C%22user_pin_required%22%3Atrue%7D%7D%2C%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.research.identiproof.io%22%7D'
    )

    const client = await OpenID4VCIClient.fromURI({ uri, flowType: AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW })
    expect(client.credentialOffer).toEqual({
      baseUrl: 'http://issuer-example.com',
      request: {
        credential_issuer: 'https://issuer.research.identiproof.io',
        grants: {
          authorization_code: {
            issuer_state: 'previously-created-state',
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'test_code',
            user_pin_required: true,
          },
        },
      },
      version: 1011,
    })
  })

  it('should create credential offer uri', async () => {
    await expect(
      vcIssuer.createCredentialOfferURI({
        grants: {
          authorization_code: {
            issuer_state: issuerState,
          },
        },
        scheme: 'http',
        baseUri: 'issuer-example.com',
        credentials: [''],
        credentialOfferUri: 'https://somehost.com/offer-id',
      })
    ).resolves.toEqual('http://issuer-example.com?credential_offer_uri=https://somehost.com/offer-id')
  })

  it('should fail issuing credential if an invalid state is used', async () => {
    await expect(
      vcIssuer.issueCredentialFromIssueRequest({
        issueCredentialRequest: {
          type: ['VerifiableCredential'],
          format: 'jwt_vc_json',
          proof: 'ye.ye.ye',
        } as unknown as CredentialRequest,
        issuerState: 'invalid state',
      })
    ).rejects.toThrow(Error(STATE_MISSING_ERROR))
  })

  it('should issue credential if a valid state is passed in', async () => {
    await expect(
      vcIssuer.issueCredentialFromIssueRequest({
        issueCredentialRequest: {
          type: ['VerifiableCredential'],
          format: 'jwt_vc_json',
          proof: 'ye.ye.ye',
        } as unknown as CredentialRequest,
        issuerState,
      })
    ).resolves.toEqual({
      c_nonce: expect.any(String),
      c_nonce_expires_in: 90000,
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        credentialSubject: {},
        issuanceDate: expect.any(String),
        issuer: 'did:key:test',
        proof: {
          created: expect.any(String),
          jwt: 'ye.ye.ye',
          proofPurpose: 'assertionMethod',
          type: 'JwtProof2020',
          verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf',
        },
        type: ['VerifiableCredential'],
      },
      format: 'jwt_vc_json',
    })
  })
})
