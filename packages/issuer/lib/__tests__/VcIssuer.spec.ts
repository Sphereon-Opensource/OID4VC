import {
  Alg,
  CredentialFormatEnum,
  CredentialRequest,
  CredentialSupported,
  Display,
  IssuerCredentialSubjectDisplay,
} from '@sphereon/openid4vci-common'
import { IProofPurpose, IProofType } from '@sphereon/ssi-types'

import { VcIssuer } from '../VcIssuer'
import { CredentialSupportedBuilderV1_11, VcIssuerBuilder } from '../builder'
import { MemoryCredentialOfferStateManager } from '../state-manager/MemoryCredentialOfferStateManager'

describe('VcIssuer', () => {
  let vcIssuer: VcIssuer

  beforeAll(async () => {
    const credentialsSupported: CredentialSupported = new CredentialSupportedBuilderV1_11()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat(CredentialFormatEnum.jwt_vc_json)
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
      } as Display)
      .withIssuerCredentialSubjectDisplay('given_name', {
        name: 'given name',
        locale: 'en-US',
      } as IssuerCredentialSubjectDisplay)
      .build()
    const stateManager = new MemoryCredentialOfferStateManager()
    await stateManager.setState('existing-client', {
      createdOn: +new Date(),
      credentialOffer: {
        credential_issuer: 'did:key:test',
        credential_definition: {
          types: ['VerifiableCredential'],
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          credentialSubject: {},
        },
      },
    })
    vcIssuer = new VcIssuerBuilder()
      .withAuthorizationServer('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer('https://credential-issuer')
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withCredentialsSupported(credentialsSupported)
      .withCredentialOfferStateManager(stateManager)
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

  it('should fail at the first interaction of the client with the issuer', async () => {
    await expect(
      vcIssuer.issueCredentialFromIssueRequest(
        {
          type: ['VerifiableCredential'],
          format: 'jwt_vc_json',
          proof: 'ye.ye.ye',
        } as unknown as CredentialRequest,
        'test-code'
      )
    ).rejects.toThrow(Error('The client is not known by the issuer'))
  })

  it('should succeed if the client already interacted with the issuer', async () => {
    await expect(
      vcIssuer.issueCredentialFromIssueRequest(
        {
          type: ['VerifiableCredential'],
          format: 'jwt_vc_json',
          proof: 'ye.ye.ye',
        } as unknown as CredentialRequest,
        'existing-client'
      )
    ).resolves.toEqual({
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
