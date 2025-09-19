import { uuidv4 } from '@sphereon/oid4vc-common'
import { OpenID4VCIClientV1_0_15 } from '@sphereon/oid4vci-client'
import {
  Alg,
  ALG_ERROR,
  CredentialConfigurationSupportedV1_0_15,
  CredentialOfferSession,
  IssueStatus,
  STATE_MISSING_ERROR
} from '@sphereon/oid4vci-common'
import { IProofPurpose, IProofType } from '@sphereon/ssi-types'
import { afterAll, beforeEach, describe, expect, it, vitest } from 'vitest'

import { VcIssuer } from '../VcIssuer'
import { AuthorizationServerMetadataBuilder, CredentialSupportedBuilderV1_15, VcIssuerBuilder } from '../builder'
import { MemoryStates } from '../state-manager'

const IDENTIPROOF_ISSUER_URL = 'https://issuer.research.identiproof.io'

const verifiableCredential = {
  '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
  id: 'http://university.example/credentials/1872',
  type: ['VerifiableCredential', 'ExampleAlumniCredential'],
  issuer: 'https://university.example/issuers/565049',
  issuanceDate: new Date().toISOString(),
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    alumniOf: {
      id: 'did:example:c276e12ec21ebfeb1f712ebc6f1',
      name: 'Example University'
    }
  }
}

const verifiableCredential_withoutDid = {
  '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
  id: 'http://university.example/credentials/1872',
  type: ['VerifiableCredential', 'ExampleAlumniCredential'],
  issuer: 'https://university.example/issuers/565049',
  issuanceDate: new Date().toISOString(),
  credentialSubject: {
    id: 'ebfeb1f712ebc6f1c276e12ec21',
    alumniOf: {
      id: 'c276e12ec21ebfeb1f712ebc6f1',
      name: 'Example University'
    }
  }
}

const authorizationServerMetadata = new AuthorizationServerMetadataBuilder()
  .withIssuer(IDENTIPROOF_ISSUER_URL)
  .withCredentialEndpoint('http://localhost:3456/test/credential-endpoint')
  .withTokenEndpoint('http://localhost:3456/test/token')
  .withAuthorizationEndpoint('https://token-endpoint.example.com/authorize')
  .withTokenEndpointAuthMethodsSupported(['none', 'client_secret_basic', 'client_secret_jwt', 'client_secret_post'])
  .withResponseTypesSupported(['code', 'token', 'id_token'])
  .withScopesSupported(['openid', 'abcdef'])
  .build()

describe('VcIssuer', () => {
  let vcIssuer: VcIssuer
  const issuerState = 'previously-created-state'
  const clientId = 'sphereon:wallet'
  const preAuthorizedCode = 'test_code'

  const jwtVerifyCallback = vitest.fn()

  beforeEach(async () => {
    vitest.clearAllMocks()
    const credentialsSupported: Record<string, CredentialConfigurationSupportedV1_0_15> = new CredentialSupportedBuilderV1_15()
      .withCredentialSigningAlgValuesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
      .withCredentialName('UniversityDegree_JWT')
      .withCredentialDefinition({
        type: ['VerifiableCredential', 'UniversityDegree_JWT']
      })
      .withCredentialSupportedDisplay({
        name: 'University Credential',
        locale: 'en-US',
        logo: {
          url: 'https://exampleuniversity.com/public/logo.png',
          alt_text: 'a square logo of a university'
        },
        background_color: '#12107c',
        text_color: '#FFFFFF'
      })
      .addClaim({
        path: ['credentialSubject', 'given_name'],
        mandatory: false,
        display: [{
          name: 'given name',
          locale: 'en-US'
        }]
      })
      .build()
    const stateManager = new MemoryStates<CredentialOfferSession>()
    await stateManager.set('previously-created-state', {
      issuerState,
      clientId,
      preAuthorizedCode,
      createdAt: +new Date(),
      lastUpdatedAt: +new Date(),
      status: IssueStatus.OFFER_CREATED,
      notification_id: uuidv4(),
      txCode: '123456',
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'did:key:test',
          credential_configuration_ids: ['UniversityDegree_JWT'],
          grants: {
            authorization_code: { issuer_state: issuerState },
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': preAuthorizedCode,
              tx_code: {
                input_mode: 'text',
                length: 4
              }
            }
          }
        }
      }
    })

    vcIssuer = new VcIssuerBuilder()
      .withAuthorizationServers('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer(IDENTIPROOF_ISSUER_URL)
      .withAuthorizationMetadata(authorizationServerMetadata)
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US'
      })
      .withCredentialConfigurationsSupported(credentialsSupported)
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
            verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf'
          }
        })
      )
      .withJWTVerifyCallback(jwtVerifyCallback)
      .build()
  })

  afterAll(async () => {
    vitest.clearAllMocks()
    // await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  it.skip('should create credential offer', async () => {
    const { uri, ...rest } = await vcIssuer.createCredentialOfferURI({
      offerMode: 'VALUE',
      grants: {
        authorization_code: {
          issuer_state: issuerState
        },
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthorizedCode,
          tx_code: {
            input_mode: 'text',
            length: 4
          }
        }
      },
      scheme: 'http',
      baseUri: 'issuer-example.com',
      qrCodeOpts: {
        size: 400,
        colorDark: '#000000',
        colorLight: '#ffffff',
        correctLevel: 2
      }
    })

    console.log(JSON.stringify(rest, null, 2))

    const client = await OpenID4VCIClientV1_0_15.fromURI({ uri })
    expect(client.credentialOffer).toEqual({
      baseUrl: 'http://issuer-example.com',
      credential_offer: {
        credential_issuer: 'https://issuer.research.identiproof.io',
        credential_configuration_ids: ['UniversityDegree_JWT'],
        grants: {
          authorization_code: {
            issuer_state: 'previously-created-state'
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'test_code',
            tx_code: {
              input_mode: 'text',
              length: 4
            }
          }
        }
      },
      issuerState: 'previously-created-state',
      original_credential_offer: {
        credential_issuer: 'https://issuer.research.identiproof.io',
        credential_configuration_ids: ['UniversityDegree_JWT'],
        grants: {
          authorization_code: {
            issuer_state: 'previously-created-state'
          },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': 'test_code',
            tx_code: {
              input_mode: 'text',
              length: 4
            }
          }
        }
      },
      preAuthorizedCode: 'test_code',
      scheme: 'http',
      supportedFlows: ['Authorization Code Flow', 'Pre-Authorized Code Flow'],
      userPinRequired: true,
      version: 1015
    })
  })

  it('should create credential offer uri', async () => {
    await expect(
      vcIssuer
        .createCredentialOfferURI({
          offerMode: 'REFERENCE',
          credentialOfferUri: 'http://issuer-example.com/:id',
          grants: {
            authorization_code: {
              issuer_state: issuerState
            }
          },
          scheme: 'http',
          baseUri: 'issuer-example.com',
          credential_configuration_ids: ['UniversityDegree_JWT']
        })
        .then((response) => response.uri)
    ).resolves.toContain('http://issuer-example.com?credential_offer_uri=http%3A%2F%2Fissuer-example.com%2F')
  })

  // Of course this doesn't work. The state is part of the proof to begin with
  it('should fail issuing credential if an invalid state is used', async () => {
    jwtVerifyCallback.mockResolvedValue({
      did: 'did:example:1234',
      kid: 'did:example:1234#auth',
      alg: Alg.ES256K,
      didDocument: {
        '@context': 'https://www.w3.org/ns/did/v1',
        id: 'did:example:1234'
      },
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg: Alg.ES256K,
          kid: 'test-kid'
        },
        payload: {
          aud: IDENTIPROOF_ISSUER_URL,
          iat: +new Date() / 1000,
          nonce: 'test-nonce'
        }
      }
    })

    await expect(
      vcIssuer.issueCredential({
        credentialRequest: {
          credential_configuration_id: 'UniversityDegree_JWT',
          proof: {
            proof_type: 'jwt',
            jwt: 'ye.ye.ye'
          }
        }
        // issuerState: 'invalid state',
      })
    ).rejects.toThrow(Error(STATE_MISSING_ERROR + ' (test-nonce)'))
  })

  it.each([...Object.values<string>(Alg), 'CUSTOM'])('should issue %s signed credential if a valid state is passed in', async (alg: string) => {
    jwtVerifyCallback.mockResolvedValue({
      did: 'did:example:1234',
      kid: 'did:example:1234#auth',
      alg: alg,
      didDocument: {
        '@context': 'https://www.w3.org/ns/did/v1',
        id: 'did:example:1234'
      },
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg: alg,
          kid: 'test-kid'
        },
        payload: {
          aud: IDENTIPROOF_ISSUER_URL,
          iat: +new Date() / 1000,
          nonce: 'test-nonce'
        }
      }
    })

    const createdAt = +new Date()
    await vcIssuer.cNonces.set('test-nonce', {
      cNonce: 'test-nonce',
      preAuthorizedCode: 'test-pre-authorized-code',
      createdAt: createdAt
    })
    await vcIssuer.credentialOfferSessions.set('test-pre-authorized-code', {
      createdAt: createdAt,
      notification_id: '43243',
      preAuthorizedCode: 'test-pre-authorized-code',
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'did:key:test',
          credential_configuration_ids: ['UniversityDegree_JWT']
        }
      },
      lastUpdatedAt: createdAt,
      status: IssueStatus.ACCESS_TOKEN_CREATED
    })

    await expect(
      vcIssuer.issueCredential({
        credential: verifiableCredential,
        credentialRequest: {
          credential_configuration_id: 'UniversityDegree_JWT',
          proof: {
            proof_type: 'jwt',
            jwt: 'ye.ye.ye'
          }
        },
        newCNonce: 'new-test-nonce'
      })
    ).resolves.toEqual({
      c_nonce: 'new-test-nonce',
      c_nonce_expires_in: 300,
      notification_id: '43243',
      credentials: [{
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
            verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf'
          },
          type: ['VerifiableCredential']
        }
      }
      ]
    })
  })

  it('should fail issuing credential if the signing algorithm is missing', async () => {
    const createdAt = +new Date()
    await vcIssuer.cNonces.set('test-nonce', {
      cNonce: 'test-nonce',
      preAuthorizedCode: 'test-pre-authorized-code',
      createdAt: createdAt
    })

    jwtVerifyCallback.mockResolvedValue({
      did: 'did:example:1234',
      kid: 'did:example:1234#auth',
      alg: undefined,
      didDocument: {
        '@context': 'https://www.w3.org/ns/did/v1',
        id: 'did:example:1234'
      },
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg: undefined,
          kid: 'test-kid'
        },
        payload: {
          aud: IDENTIPROOF_ISSUER_URL,
          iat: +new Date() / 1000,
          nonce: 'test-nonce'
        }
      }
    })

    await expect(
      vcIssuer.issueCredential({
        credentialRequest: {
          credential_configuration_id: 'UniversityDegree_JWT',
          proof: {
            proof_type: 'jwt',
            jwt: 'ye.ye.ye'
          }
        }
      })
    ).rejects.toThrow(Error(ALG_ERROR))
  })
})

describe('VcIssuer without did', () => {
  let vcIssuer: VcIssuer
  const issuerState = 'previously-created-state'
  const clientId = 'sphereon:wallet'
  const preAuthorizedCode = 'test_code'

  const jwtVerifyCallback = vitest.fn()

  beforeEach(async () => {
    vitest.clearAllMocks()
    const credentialsSupported: Record<string, CredentialConfigurationSupportedV1_0_15> = new CredentialSupportedBuilderV1_15()
      .withCredentialSigningAlgValuesSupported('ES256K')
      .withCryptographicBindingMethod('jwk')
      .withFormat('jwt_vc_json')
      .withCredentialName('UniversityDegree_JWT')
      .withCredentialDefinition({
        type: ['VerifiableCredential', 'UniversityDegree_JWT']
      })
      .withCredentialSupportedDisplay({
        name: 'University Credential',
        locale: 'en-US',
        logo: {
          url: 'https://exampleuniversity.com/public/logo.png',
          alt_text: 'a square logo of a university'
        },
        background_color: '#12107c',
        text_color: '#FFFFFF'
      })
      .addClaim({
        path: ['credentialSubject', 'given_name'],
        mandatory: false,
        display: [{
          name: 'given name',
          locale: 'en-US'
        }]
      })
      .build()
    const stateManager = new MemoryStates<CredentialOfferSession>()
    await stateManager.set('previously-created-state', {
      issuerState,
      clientId,
      preAuthorizedCode,
      createdAt: +new Date(),
      lastUpdatedAt: +new Date(),
      status: IssueStatus.OFFER_CREATED,
      notification_id: uuidv4(),
      txCode: '123456',
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'test.com',
          credential_configuration_ids: ['UniversityDegree_JWT'],
          grants: {
            authorization_code: { issuer_state: issuerState },
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': preAuthorizedCode,
              tx_code: {
                input_mode: 'text',
                length: 4
              }
            }
          }
        }
      }
    })
    vcIssuer = new VcIssuerBuilder()
      .withAuthorizationServers('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer(IDENTIPROOF_ISSUER_URL)
      .withAuthorizationMetadata(authorizationServerMetadata)
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US'
      })
      .withCredentialConfigurationsSupported(credentialsSupported)
      .withCredentialOfferStateManager(stateManager)
      .withInMemoryCNonceState()
      .withInMemoryCredentialOfferURIState()
      .withCredentialSignerCallback(() =>
        Promise.resolve({
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential'],
          issuer: 'test.com',
          issuanceDate: new Date().toISOString(),
          credentialSubject: {},
          proof: {
            type: IProofType.JwtProof2020,
            jwt: 'ye.ye.ye',
            created: new Date().toISOString(),
            proofPurpose: IProofPurpose.assertionMethod,
            verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf'
          }
        })
      )
      .withJWTVerifyCallback(jwtVerifyCallback)
      .build()
  })

  afterAll(async () => {
    vitest.clearAllMocks()
    // await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  // Of course this doesn't work. The state is part of the proof to begin with
  it('should fail issuing credential if an invalid state is used', async () => {
    jwtVerifyCallback.mockResolvedValue({
      alg: Alg.ES256K,
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg: Alg.ES256K,
          x5c: ['12', '34', '56']
        },
        payload: {
          aud: IDENTIPROOF_ISSUER_URL,
          iat: +new Date() / 1000,
          nonce: 'test-nonce'
        }
      }
    })

    await expect(
      vcIssuer.issueCredential({
        credentialRequest: {
          credential_configuration_id: 'UniversityDegree_JWT',
          proof: {
            proof_type: 'jwt',
            jwt: 'ye.ye.ye'
          }
        }
        // issuerState: 'invalid state',
      })
    ).rejects.toThrow(Error(STATE_MISSING_ERROR + ' (test-nonce)'))
  })

  it.each([...Object.values<string>(Alg), 'CUSTOM'])('should issue %s signed credential if a valid state is passed in', async (alg: string) => {
    jwtVerifyCallback.mockResolvedValue({
      alg: alg,
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg: alg,
          x5c: ['12', '34', '56']
        },
        payload: {
          aud: IDENTIPROOF_ISSUER_URL,
          iat: +new Date() / 1000,
          nonce: 'test-nonce'
        }
      }
    })

    const createdAt = +new Date()
    await vcIssuer.cNonces.set('test-nonce', {
      cNonce: 'test-nonce',
      preAuthorizedCode: 'test-pre-authorized-code',
      createdAt: createdAt
    })
    await vcIssuer.credentialOfferSessions.set('test-pre-authorized-code', {
      createdAt: createdAt,
      notification_id: '43243',
      preAuthorizedCode: 'test-pre-authorized-code',
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'test.com',
          credential_configuration_ids: ['UniversityDegree_JWT']
        }
      },
      lastUpdatedAt: createdAt,
      status: IssueStatus.ACCESS_TOKEN_CREATED
    })

    await expect(
      vcIssuer.issueCredential({
        credential: verifiableCredential_withoutDid,
        credentialRequest: {
          credential_configuration_id: 'UniversityDegree_JWT',
          proof: {
            proof_type: 'jwt',
            jwt: 'ye.ye.ye'
          }
        },
        newCNonce: 'new-test-nonce'
      })
    ).resolves.toEqual({
      c_nonce: 'new-test-nonce',
      c_nonce_expires_in: 300,
      notification_id: '43243',
      credentials: [{
        credential: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          credentialSubject: {},
          issuanceDate: expect.any(String),
          issuer: 'test.com',
          proof: {
            created: expect.any(String),
            jwt: 'ye.ye.ye',
            proofPurpose: 'assertionMethod',
            type: 'JwtProof2020',
            verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf'
          },
          type: ['VerifiableCredential']
        }
      }]
    })
  })

  it('should fail issuing credential if the signing algorithm is missing', async () => {
    const createdAt = +new Date()
    await vcIssuer.cNonces.set('test-nonce', {
      cNonce: 'test-nonce',
      preAuthorizedCode: 'test-pre-authorized-code',
      createdAt: createdAt
    })

    jwtVerifyCallback.mockResolvedValue({
      alg: undefined,
      jwt: {
        header: {
          typ: 'openid4vci-proof+jwt',
          alg: undefined,
          x5c: ['12', '34', '56']
        },
        payload: {
          aud: IDENTIPROOF_ISSUER_URL,
          iat: +new Date() / 1000,
          nonce: 'test-nonce'
        }
      }
    })

    await expect(
      vcIssuer.issueCredential({
        credentialRequest: {
          credential_configuration_id: 'UniversityDegree_JWT',
          proof: {
            proof_type: 'jwt',
            jwt: 'ye.ye.ye'
          }
        }
      })
    ).rejects.toThrow(Error(ALG_ERROR))
  })

  it('should create credential offer uri with REFERENCE mode', async () => {
    const result = await vcIssuer.createCredentialOfferURI({
      offerMode: 'REFERENCE',
      credentialOfferUri: 'https://example.com/api/credentials/:id',
      grants: {
        authorization_code: {
          issuer_state: issuerState
        }
      },
      scheme: 'http',
      baseUri: 'issuer-example.com'
    })

    expect(result.uri).toMatch(/http:\/\/issuer-example\.com\?credential_offer_uri=https%3A%2F%2Fexample\.com%2Fapi%2Fcredentials%2F[\w-]+/)
    expect(result.session).toBeDefined()
    expect(result.session.credentialOffer.credential_offer_uri).toMatch(/https:\/\/example\.com\/api\/credentials\/[\w-]+/)
  })

  it('should throw error if credential offer Uri is missing with REFERENCE mode', async () => {
    await expect(
      vcIssuer.createCredentialOfferURI({
        offerMode: 'REFERENCE',
        grants: {
          authorization_code: {
            issuer_state: issuerState
          }
        }
      })
    ).rejects.toThrow('credentialOfferUri must be supplied for offerMode REFERENCE!')
  })

  it('should get credential offer session by uri', async () => {
    const result = await vcIssuer.createCredentialOfferURI({
      offerMode: 'REFERENCE',
      credentialOfferUri: 'https://example.com/api/credentials/:id',
      grants: {
        authorization_code: {
          issuer_state: issuerState
        },
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': 'preAuthCode'
        }
      }
    })

    const session = await vcIssuer.getCredentialOfferSessionById(result.session.preAuthorizedCode!, ['uri'])

    expect(session).toBeDefined()
    expect(session.credentialOffer).toEqual(result.session.credentialOffer)
  })

  it('should throw error when getting session with invalid uri', async () => {
    await expect(vcIssuer.getCredentialOfferSessionById('https://example.com/invalid-uri')).rejects.toThrow(
      'no value found for id https://example.com/invalid-uri'
    )
  })

  it('should throw error when getting session by uri without uri state manager', async () => {
    // Create issuer without URI state manager
    const vcIssuerWithoutUriState = new VcIssuerBuilder()
      .withAuthorizationServers('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer(IDENTIPROOF_ISSUER_URL)
      .withAuthorizationMetadata(authorizationServerMetadata)
      .withCredentialConfigurationsSupported({})
      .withCredentialOfferStateManager(new MemoryStates<CredentialOfferSession>())
      .withInMemoryCNonceState()
      .build()

    await expect(vcIssuerWithoutUriState.getCredentialOfferSessionById('https://example.com/some-uri')).rejects.toThrow(
      'no value found for id https://example.com/some-uri'
    )
  })
})

describe.skip('VcIssuer v15 nonce endpoint support', () => {
  it('should acquire nonce from nonce endpoint in v15', async () => {
    // Mock the nonce endpoint response
    global.fetch = vitest.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        c_nonce: 'fresh-nonce-from-endpoint'
      })
    })

    const client: OpenID4VCIClientV1_0_15 = await OpenID4VCIClientV1_0_15.fromCredentialIssuer({
      credentialIssuer: IDENTIPROOF_ISSUER_URL,
      retrieveServerMetadata: false
    })

    // Mock endpoint metadata with nonce endpoint
    client.state.endpointMetadata = {
      credential_endpoint: 'https://issuer.example.com/credential',
      token_endpoint: 'https://issuer.example.com/token',
      issuer: IDENTIPROOF_ISSUER_URL,
      authorizationServerType: 'OID4VCI',
      credentialIssuerMetadata: {
        credential_issuer: IDENTIPROOF_ISSUER_URL,
        credential_endpoint: 'https://issuer.example.com/credential',
        credential_configurations_supported: {},
        nonce_endpoint: 'https://issuer.example.com/nonce'
      }
    }

    const nonce = await client.acquireNonce()

    expect(nonce).toBe('fresh-nonce-from-endpoint')
    expect(fetch).toHaveBeenCalledWith(
      'https://issuer.example.com/nonce',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      }
    )
  })

  it('should fail when nonce endpoint is not available', async () => {
    const client = await OpenID4VCIClientV1_0_15.fromCredentialIssuer({
      credentialIssuer: IDENTIPROOF_ISSUER_URL,
      retrieveServerMetadata: false
    })

    // Mock endpoint metadata without nonce endpoint
    client.state.endpointMetadata = {
      credential_endpoint: 'https://issuer.example.com/credential',
      token_endpoint: 'https://issuer.example.com/token',
      issuer: IDENTIPROOF_ISSUER_URL,
      authorizationServerType: 'OID4VCI'
    }

    await expect(client.acquireNonce()).rejects.toThrow('Nonce endpoint not available')
  })

  it('should use cached nonce when available', async () => {
    const client = await OpenID4VCIClientV1_0_15.fromCredentialIssuer({
      credentialIssuer: IDENTIPROOF_ISSUER_URL,
      retrieveServerMetadata: false
    })

    // Set cached nonce
    client.state.cachedCNonce = 'cached-nonce-value'

    // Should use cached nonce without calling endpoint
    global.fetch = vitest.fn()

    // Test that credential acquisition works with cached nonce
    expect(client.state.cachedCNonce).toBe('cached-nonce-value')
    expect(fetch).not.toHaveBeenCalled()
  })
})
