import { ICredentialSupportedV1_11 } from '@sphereon/openid4vci-common'

import {CredentialSupportedV1_11Builder, VcIssuer, VcIssuerBuilder} from '../lib'
import { createCredentialOfferDeeplink } from '../lib/functions/CredentialOffer'

describe('VcIssuer should', () => {
  it('create a CredentialOffer deeplink', () => {
    const credentialsSupported: ICredentialSupportedV1_11 = new CredentialSupportedV1_11Builder()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
      .withId('UniversityDegree_JWT')
      .withTypes(['VerifiableCredential', 'UniversityDegreeCredential'])
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

    const deeplink = createCredentialOfferDeeplink(
      '4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp',
      vcIssuer._issuerMetadata
    )
    const urlParams = new URLSearchParams(deeplink)
    expect(urlParams.get('grants')).toBeDefined()
  })

  //fixme: this test should change after we've an actual signing mechanism in place
  it('should ', async () => {
    const credentialRequeset = {
      "format":"jwt_vc_json",
      "types":[
        "VerifiableCredential",
        "UniversityDegreeCredential"
      ],
      "proof":{
        "proof_type":"jwt",
        "jwt":"eyJraWQiOiJkaWQ6ZXhhbXBsZTplYmZlYjFmNzEyZWJjNmYxYzI3NmUxMmVjMjEva2V5cy8xIiwiYWxnIjoiRVMyNTYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJzNkJoZFJrcXQzIiwiYXVkIjoiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLCJpYXQiOiIyMDE4LTA5LTE0VDIxOjE5OjEwWiIsIm5vbmNlIjoidFppZ25zbkZicCJ9.ewdkIkPV50iOeBUqMXCC_aZKPxgihac0aW9EkL1nOzM"
      }
    }
    const vcIssuer = createDummyIssuer()
    const credentialResponse = await vcIssuer.issueCredentialFromIssueRequest(credentialRequeset)
    expect(credentialResponse.credential).toBeDefined()
  });

  // below is the helper function for testing issue verifiable credential
  function createDummyIssuer(): VcIssuer {
    const credentialsSupported: ICredentialSupportedV1_11 = new CredentialSupportedV1_11Builder()
    .withCryptographicSuitesSupported('ES256K')
    .withCryptographicBindingMethod('did')
    .withFormat('jwt_vc_json')
    .withId('UniversityDegree_JWT')
    .withTypes(['VerifiableCredential', 'UniversityDegreeCredential'])
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
    return new VcIssuerBuilder()
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
  }
})
