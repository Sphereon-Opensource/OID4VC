import { OpenID4VCIClient } from '@sphereon/oid4vci-client'
import {
  Alg,
  AuthzFlowType,
  CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11,
  CredentialOfferSession,
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
    jest.clearAllMocks()
    const credentialsSupported: CredentialSupported = new CredentialSupportedBuilderV1_11()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
      .withTypes('VerifiableCredential')
      .withId('UniversityDegree_JWT')
      .withCredentialSupportedDisplay({
        name: 'University Credential',
        locale: 'en-US',
        logo: {
          url: 'https://exampleuniversity.com/public/logo.png',
          alt_text: 'a square logo of a university',
        },
        background_color: '#12107c',
        text_color: '#FFFFFF',
      })
      .addCredentialSubjectPropertyDisplay('given_name', {
        name: 'given name',
        locale: 'en-US',
      } as IssuerCredentialSubjectDisplay)
      .build()
    const stateManager = new MemoryStates<CredentialOfferSession>()
    await stateManager.set('previously-created-state', {
      issuerState,
      clientId,
      preAuthorizedCode,
      createdAt: +new Date(),
      userPin: '123456',
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
      .withCredentialSignerCallback(() =>
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
    jest.clearAllMocks()
    // await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
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
      'http://issuer-example.com?credential_offer=%7B%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22previously-created-state%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22test_code%22%2C%22user_pin_required%22%3Atrue%7D%7D%2C%22credential_issuer%22%3A%22https%3A%2F%2Fissuer.research.identiproof.io%22%2C%22credentials%22%3A%5B%7B%22format%22%3A%22jwt_vc_json%22%2C%22types%22%3A%5B%22VerifiableCredential%22%5D%2C%22credentialSubject%22%3A%7B%22given_name%22%3A%7B%22name%22%3A%22given%20name%22%2C%22locale%22%3A%22en-US%22%7D%7D%2C%22cryptographic_suites_supported%22%3A%5B%22ES256K%22%5D%2C%22cryptographic_binding_methods_supported%22%3A%5B%22did%22%5D%2C%22id%22%3A%22UniversityDegree_JWT%22%2C%22display%22%3A%5B%7B%22name%22%3A%22University%20Credential%22%2C%22locale%22%3A%22en-US%22%2C%22logo%22%3A%7B%22url%22%3A%22https%3A%2F%2Fexampleuniversity.com%2Fpublic%2Flogo.png%22%2C%22alt_text%22%3A%22a%20square%20logo%20of%20a%20university%22%7D%2C%22background_color%22%3A%22%2312107c%22%2C%22text_color%22%3A%22%23FFFFFF%22%7D%5D%7D%5D%7D'
    )

    const client = await OpenID4VCIClient.fromURI({ uri, flowType: AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW })
    expect(client.credentialOffer).toEqual({
      baseUrl: 'http://issuer-example.com',
      credential_offer: {
        credential_issuer: 'https://issuer.research.identiproof.io',
        credentials: [
          {
            credentialSubject: {
              given_name: {
                locale: 'en-US',
                name: 'given name',
              },
            },
            cryptographic_binding_methods_supported: ['did'],
            cryptographic_suites_supported: ['ES256K'],
            display: [
              {
                background_color: '#12107c',
                locale: 'en-US',
                logo: {
                  alt_text: 'a square logo of a university',
                  url: 'https://exampleuniversity.com/public/logo.png',
                },
                name: 'University Credential',
                text_color: '#FFFFFF',
              },
            ],
            format: 'jwt_vc_json',
            id: 'UniversityDegree_JWT',
            types: ['VerifiableCredential'],
          },
        ],
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
      issuerState: 'previously-created-state',
      original_credential_offer: {
        credential_issuer: 'https://issuer.research.identiproof.io',
        credentials: [
          {
            credentialSubject: {
              given_name: {
                locale: 'en-US',
                name: 'given name',
              },
            },
            cryptographic_binding_methods_supported: ['did'],
            cryptographic_suites_supported: ['ES256K'],
            display: [
              {
                background_color: '#12107c',
                locale: 'en-US',
                logo: {
                  alt_text: 'a square logo of a university',
                  url: 'https://exampleuniversity.com/public/logo.png',
                },
                name: 'University Credential',
                text_color: '#FFFFFF',
              },
            ],
            format: 'jwt_vc_json',
            id: 'UniversityDegree_JWT',
            types: ['VerifiableCredential'],
          },
        ],
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
      preAuthorizedCode: 'test_code',
      scheme: 'http',
      supportedFlows: ['Authorization Code Flow', 'Pre-Authorized Code Flow'],
      userPinRequired: true,
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

  // Of course this doesn't work. The state is part of the proof to begin with
  it('should fail issuing credential if an invalid state is used', async () => {
    await expect(
      vcIssuer.issueCredential({
        credentialRequest: {
          types: ['VerifiableCredential'],
          format: 'jwt_vc_json',
          proof: {
            proof_type: 'openid4vci-proof+jwt',
            jwt: 'ye.ye.ye',
          },
        },
        // issuerState: 'invalid state',
      })
    ).rejects.toThrow(Error(STATE_MISSING_ERROR + ' (test-nonce)'))
  })

  // Of course this doesn't work. The state is part of the proof to begin with
  xit('should issue credential if a valid state is passed in', async () => {
    await expect(
      vcIssuer.issueCredential({
        credentialRequest: {
          types: ['VerifiableCredential'],
          format: 'jwt_vc_json',
          proof: {
            proof_type: 'openid4vci-proof+jwt',
            jwt: 'ye.ye.ye',
          },
        },
        // issuerState,
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
