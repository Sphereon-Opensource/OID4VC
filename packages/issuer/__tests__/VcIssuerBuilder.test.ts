import { CredentialSupportedV1_11Builder } from '../lib/CredentialSupportedV1_11Builder'
import { VcIssuerBuilder } from '../lib/VcIssuerBuilder'
import { CredentialErrorResponse, ICredentialSupportedV1_11 } from '../types'

describe('VcIssuer builder should', () => {
  it('generate a VcIssuer', () => {
    const credentialsSupported: ICredentialSupportedV1_11 = new CredentialSupportedV1_11Builder()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
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
      })
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
      .build()

    expect(vcIssuer.getIssuerMetadata().authorization_server).toEqual('https://authorization-server')
    expect(vcIssuer.getIssuerMetadata().display).toBeDefined()
    expect(vcIssuer.getIssuerMetadata().credentials_supported[0].id).toEqual('UniversityDegree_JWT')
  })

  it('fail to generate a VcIssuer', () => {
    const credentialsSupported: ICredentialSupportedV1_11 = new CredentialSupportedV1_11Builder()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
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
      })
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
    ).toThrowError(CredentialErrorResponse.invalid_request)
  })

  it('fail to generate a CredentialSupportedV1_11', () => {
    expect(() =>
      new CredentialSupportedV1_11Builder()
        .withCryptographicSuitesSupported('ES256K')
        .withCryptographicBindingMethod('did')
        .withId('UniversityDegree_JWT')
        .build()
    ).toThrowError(CredentialErrorResponse.invalid_request)
  })
})
