import { uuidv4 } from '@sphereon/oid4vc-common'
import { CredentialConfigurationSupportedV1_0_13, IssuerCredentialSubjectDisplay, IssueStatus, TokenErrorResponse } from '@sphereon/oid4vci-common'

import { AuthorizationServerMetadataBuilder } from '../builder/AuthorizationServerMetadataBuilder'
import { CredentialSupportedBuilderV1_13, VcIssuerBuilder } from '../index'


const authorizationServerMetadata = new AuthorizationServerMetadataBuilder()
  .withIssuer('https://credential-issuer')
  .withCredentialEndpoint('https://credential-endpoint')
  .withTokenEndpoint('https://token-endpoint')
  .withAuthorizationEndpoint('https://token-endpoint/authorize')
  .withTokenEndpointAuthMethodsSupported(['none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post'])
  .withResponseTypesSupported(['code', 'token', 'id_token'])
  .withScopesSupported(['openid', 'abcdef'])
  .build();


describe('VcIssuer builder should', () => {
  it('generate a VcIssuer', () => {
    const credentialsSupported: Record<string, CredentialConfigurationSupportedV1_0_13> = new CredentialSupportedBuilderV1_13()
      .withCredentialSigningAlgValuesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
      .withCredentialName('UniversityDegree_JWT')
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
      .withCredentialDefinition({
        type: ['UniversityDegree_JWT'],
      })
      .addCredentialSubjectPropertyDisplay('given_name', {
        name: 'given name',
        locale: 'en-US',
      } as IssuerCredentialSubjectDisplay)
      .build()
    const vcIssuer = new VcIssuerBuilder()
      .withAuthorizationServers('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer('https://credential-issuer')
      .withAuthorizationMetadata(authorizationServerMetadata)
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withInMemoryCredentialOfferState()
      .withInMemoryCNonceState()
      .withCredentialConfigurationsSupported(credentialsSupported)
      .build()

    expect(vcIssuer.issuerMetadata.authorization_servers).toEqual(['https://authorization-server'])
    expect(vcIssuer.issuerMetadata.display).toBeDefined()
    expect(vcIssuer.issuerMetadata.credential_configurations_supported!['UniversityDegree_JWT']).toBeDefined()
  })

  it('fail to generate a VcIssuer', () => {
    const credentialsSupported: Record<string, CredentialConfigurationSupportedV1_0_13> = new CredentialSupportedBuilderV1_13()
      .withCredentialSigningAlgValuesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
      .withCredentialName('UniversityDegree_JWT')
      .withCredentialDefinition({
        type: ['VerifiableCredential', 'UniversityDegree_JWT'],
      })
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
    expect(() =>
      new VcIssuerBuilder()
        .withAuthorizationServers('https://authorization-server')
        .withCredentialEndpoint('https://credential-endpoint')
        .withIssuerDisplay({
          name: 'example issuer',
          locale: 'en-US',
        })
        .withCredentialConfigurationsSupported(credentialsSupported)
        .build(),
    ).toThrowError(TokenErrorResponse.invalid_request)
  })

  it('fail to generate a CredentialSupportedV1_11', () => {
    expect(() =>
      new CredentialSupportedBuilderV1_13()
        .withCredentialSigningAlgValuesSupported('ES256K')
        .withCryptographicBindingMethod('did')
        .withCredentialName('UniversityDegree_JWT')
        .build(),
    ).toThrowError(TokenErrorResponse.invalid_request)
  })
  it('should successfully attach an instance of the ICredentialOfferStateManager to the VcIssuer instance', async () => {
    const credentialsSupported: Record<string, CredentialConfigurationSupportedV1_0_13> = new CredentialSupportedBuilderV1_13()
      .withCredentialSigningAlgValuesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
      .withCredentialName('UniversityDegree_JWT')
      .withCredentialDefinition({
        type: ['VerifiableCredential', 'UniversityDegree_JWT'],
      })
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
    const vcIssuer = new VcIssuerBuilder()
      .withAuthorizationServers('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer('https://credential-issuer')
      .withAuthorizationMetadata(authorizationServerMetadata)
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withCredentialConfigurationsSupported(credentialsSupported)
      .withInMemoryCredentialOfferState()
      .withInMemoryCNonceState()
      .build()
    console.log(JSON.stringify(vcIssuer.issuerMetadata))
    expect(vcIssuer).toBeDefined()
    const preAuthorizedCodecreatedAt = +new Date()
    await vcIssuer.credentialOfferSessions?.set('test', {
      notification_id: uuidv4(),
      issuerState: uuidv4(),
      lastUpdatedAt: preAuthorizedCodecreatedAt,
      status: IssueStatus.OFFER_CREATED,
      clientId: 'test_client',
      createdAt: preAuthorizedCodecreatedAt,
      txCode: '123456',
      credentialOffer: { credential_offer: { credentials: ['test_credential'], credential_issuer: 'test_issuer' } },
    })
    await expect(vcIssuer.credentialOfferSessions?.get('test')).resolves.toMatchObject({
      clientId: 'test_client',
      txCode: '123456',
      status: IssueStatus.OFFER_CREATED,
      lastUpdatedAt: preAuthorizedCodecreatedAt,
      createdAt: preAuthorizedCodecreatedAt,
      credentialOffer: { credential_offer: { credentials: ['test_credential'], credential_issuer: 'test_issuer' } },
    })
  })

  it('should successfully attach an instance of the ICredentialOfferStateManager to the VcIssuer instance without did', async () => {
    const credentialsSupported: Record<string, CredentialConfigurationSupportedV1_0_13> = new CredentialSupportedBuilderV1_13()
      .withCredentialSigningAlgValuesSupported('ES256K')
      .withCryptographicBindingMethod('jwk')
      .withFormat('jwt_vc_json')
      .withCredentialName('UniversityDegree_JWT')
      .withCredentialDefinition({
        type: ['VerifiableCredential', 'UniversityDegree_JWT'],
      })
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
    const vcIssuer = new VcIssuerBuilder()
      .withAuthorizationServers('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer('https://credential-issuer')
      .withAuthorizationMetadata(authorizationServerMetadata)
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withCredentialConfigurationsSupported(credentialsSupported)
      .withInMemoryCredentialOfferState()
      .withInMemoryCNonceState()
      .build()
    expect(vcIssuer).toBeDefined()
    const preAuthorizedCodecreatedAt = +new Date()
    await vcIssuer.credentialOfferSessions?.set('test', {
      notification_id: uuidv4(),
      issuerState: uuidv4(),
      lastUpdatedAt: preAuthorizedCodecreatedAt,
      status: IssueStatus.OFFER_CREATED,
      clientId: 'test_client',
      createdAt: preAuthorizedCodecreatedAt,
      txCode: '123456',
      credentialOffer: { credential_offer: { credentials: ['test_credential'], credential_issuer: 'test_issuer' } },
    })
    await expect(vcIssuer.credentialOfferSessions?.get('test')).resolves.toMatchObject({
      clientId: 'test_client',
      txCode: '123456',
      status: IssueStatus.OFFER_CREATED,
      lastUpdatedAt: preAuthorizedCodecreatedAt,
      createdAt: preAuthorizedCodecreatedAt,
      credentialOffer: { credential_offer: { credentials: ['test_credential'], credential_issuer: 'test_issuer' } },
    })
  })
})
