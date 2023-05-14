import {
  Alg,
  CredentialFormat,
  CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11,
  CredentialOfferSession,
  CredentialRequest,
  CredentialSupported,
  IssuerCredentialSubjectDisplay,
  STATE_MISSING_ERROR,
} from '@sphereon/oid4vci-common'
import { IProofPurpose, IProofType } from '@sphereon/ssi-types'
import { v4 } from 'uuid'

import { VcIssuer } from '../VcIssuer'
import { CredentialSupportedBuilderV1_11, VcIssuerBuilder } from '../builder'
import { MemoryStates } from '../state-manager'

const IDENTIPROOF_ISSUER_URL = 'https://issuer.research.identiproof.io'

describe('VcIssuer', () => {
  let vcIssuer: VcIssuer
  const state = 'existing-client'
  const clientId = 'sphereon:wallet'

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
    await stateManager.set('existing-client', {
      id: v4(),
      clientId,
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
            authorization_code: { issuer_state: 'test_code' },
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': 'test_code',
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

  it('should fail at the first interaction of the client with the issuer', async () => {
    await expect(
      vcIssuer.issueCredentialFromIssueRequest({
        issueCredentialRequest: {
          type: ['VerifiableCredential'],
          format: 'jwt_vc_json',
          proof: 'ye.ye.ye',
        } as unknown as CredentialRequest,
        issuerState: 'first interaction',
      })
    ).rejects.toThrow(Error(STATE_MISSING_ERROR))
  })

  it('should succeed if the client already interacted with the issuer', async () => {
    await expect(
      vcIssuer.issueCredentialFromIssueRequest({
        issueCredentialRequest: {
          type: ['VerifiableCredential'],
          format: 'jwt_vc_json',
          proof: 'ye.ye.ye',
        } as unknown as CredentialRequest,
        issuerState: state,
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
