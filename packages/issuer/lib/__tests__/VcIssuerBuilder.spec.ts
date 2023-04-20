import { CredentialFormatEnum, CredentialSupported, Display, IssuerCredentialSubjectDisplay, TokenErrorResponse } from '@sphereon/openid4vci-common'

import { CredentialSupportedBuilderV1_11, VcIssuerBuilder } from '../index'
import { MemoryCredentialOfferStateManager } from '../state-manager/MemoryCredentialOfferStateManager'

describe('VcIssuer builder should', () => {
  it('generate a VcIssuer', () => {
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
    const vcIssuer = new VcIssuerBuilder()
      .withAuthorizationServer('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer('https://credential-issuer')
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withInMemoryCredentialOfferState()
      .withCredentialsSupported(credentialsSupported)
      .build()

    expect(vcIssuer.getIssuerMetadata().authorization_server).toEqual('https://authorization-server')
    expect(vcIssuer.getIssuerMetadata().display).toBeDefined()
    expect(vcIssuer.getIssuerMetadata().credentials_supported[0].id).toEqual('UniversityDegree_JWT')
  })

  it('fail to generate a VcIssuer', () => {
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
    expect(() =>
      new VcIssuerBuilder()
        .withAuthorizationServer('https://authorization-server')
        .withCredentialEndpoint('https://credential-endpoint')
        .withIssuerDisplay({
          name: 'example issuer',
          locale: 'en-US',
        })
        .withCredentialsSupported(credentialsSupported)
        .build()
    ).toThrowError(TokenErrorResponse.invalid_request)
  })

  it('fail to generate a CredentialSupportedV1_11', () => {
    expect(() =>
      new CredentialSupportedBuilderV1_11()
        .withCryptographicSuitesSupported('ES256K')
        .withCryptographicBindingMethod('did')
        .withId('UniversityDegree_JWT')
        .build()
    ).toThrowError(TokenErrorResponse.invalid_request)
  })
  it('should successfully attach an instance of the ICredentialOfferStateManager to the VcIssuer instance', async () => {
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
    const vcIssuer = new VcIssuerBuilder()
      .withAuthorizationServer('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer('https://credential-issuer')
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withCredentialsSupported(credentialsSupported)
      .withCredentialOfferStateManager(new MemoryCredentialOfferStateManager())
      .build()
    expect(vcIssuer).toBeDefined()
    const now = +new Date()
    await vcIssuer.credentialOfferStateManager?.setState('test', {
      clientId: 'test_client',
      createdOn: now,
      credentialOffer: { credentials: ['test_credential'], credential_issuer: 'test_issuer' },
    })
    await expect(vcIssuer.credentialOfferStateManager?.getState('test')).resolves.toEqual({
      clientId: 'test_client',
      createdOn: now,
      credentialOffer: { credentials: ['test_credential'], credential_issuer: 'test_issuer' },
    })
  })
})
