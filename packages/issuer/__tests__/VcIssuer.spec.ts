import { ICredentialSupportedV1_11 } from '@sphereon/openid4vci-common'

import { CredentialSupportedV1_11Builder, VcIssuerBuilder } from '../lib'
import {createCredentialOfferDeeplink} from "../lib/functions/CredentialOffer";

describe('VcIssuer should', () => {
  it('create a CredentialOffer deeplink', () => {
    const credentialsSupported: ICredentialSupportedV1_11 = new CredentialSupportedV1_11Builder()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
      .withId('UniversityDegree_JWT')
      .withTypes([
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ])
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
      .withUserPinRequired(true)
      .withAuthorizationServer('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer('https://credential-issuer')
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withCredentialsSupported(credentialsSupported)
      .build()

    const deeplink = createCredentialOfferDeeplink('4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp', vcIssuer._issuerMetadata)
    const urlParams = new URLSearchParams(deeplink)
    expect(urlParams.get('grants')).toBeDefined()
  })
})
