import { KeyObject } from 'crypto'

import * as didKeyDriver from '@digitalcredentials/did-method-key'
import { OpenID4VCIClient } from '@sphereon/oid4vci-client'
import {
  AccessTokenResponse,
  Alg,
  AuthzFlowType,
  CredentialOfferSession,
  CredentialSupported,
  IssuerCredentialSubjectDisplay,
  Jwt,
  OpenId4VCIVersion,
} from '@sphereon/oid4vci-common'
import { VcIssuer } from '@sphereon/oid4vci-issuer/dist/VcIssuer'
import { CredentialSupportedBuilderV1_11, VcIssuerBuilder } from '@sphereon/oid4vci-issuer/dist/builder'
import { MemoryStates } from '@sphereon/oid4vci-issuer/dist/state-manager'
import { IProofPurpose, IProofType } from '@sphereon/ssi-types'
import * as jose from 'jose'

import { OID4VCIServer } from '../OID4VCIServer'

const ISSUER_URL = 'http://localhost:3456/test'

let subjectKeypair: KeyPair // Proof of Possession JWT
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let subjectDIDKey: { didDocument: any; keyPairs: any; methodFor: any } // Json LD VC issuance

export const generateDid = async () => {
  const didKD = didKeyDriver.driver()
  const { didDocument, keyPairs, methodFor } = await didKD.generate()
  return { didDocument, keyPairs, methodFor }
}

interface KeyPair {
  publicKey: KeyObject
  privateKey: KeyObject
}

jest.setTimeout(15000)

describe('VcIssuer', () => {
  let vcIssuer: VcIssuer
  let server: OID4VCIServer
  let accessToken: AccessTokenResponse
  const issuerState = 'previously-created-state'
  // const clientId = 'sphereon:wallet'
  const preAuthorizedCode = 'test_code'

  /*const preAuthorizedCode1 = 'SplxlOBeZQQYbYS6WxSbIA1'
  const preAuthorizedCode2 = 'SplxlOBeZQQYbYS6WxSbIA2'
  const preAuthorizedCode3 = 'SplxlOBeZQQYbYS6WxSbIA3'
*/

  beforeAll(async () => {
    jest.clearAllMocks()

    const { privateKey, publicKey } = await jose.generateKeyPair('ES256')
    subjectKeypair = { publicKey: publicKey as KeyObject, privateKey: privateKey as KeyObject }
    subjectDIDKey = await generateDid()

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const accessTokenSignerCallback = async (jwt: Jwt, kid?: string): Promise<string> => {
      const privateKey = (await jose.generateKeyPair(Alg.ES256)).privateKey as KeyObject
      return new jose.SignJWT({ ...jwt.payload }).setProtectedHeader({ ...jwt.header, alg: Alg.ES256 }).sign(privateKey)
    }

    const credentialsSupported: CredentialSupported = new CredentialSupportedBuilderV1_11()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withTypes('VerifiableCredential')
      .withFormat('jwt_vc_json')
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

    vcIssuer = new VcIssuerBuilder()
      // .withAuthorizationServer('https://authorization-server')
      .withCredentialEndpoint('http://localhost:3456/test/credential-endpoint')
      .withCredentialIssuer(ISSUER_URL)
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
      .withJWTVerifyCallback((args: { jwt: string; _kid?: string }) => {
        return Promise.resolve({
          header: jose.decodeProtectedHeader(args.jwt),
          payload: jose.decodeJwt(args.jwt),
        } as Jwt)
      })
      .build()

    server = new OID4VCIServer({
      issuer: vcIssuer,
      serverOpts: { baseUrl: 'http://localhost:3456/test', port: 3456 },
      tokenEndpointOpts: { accessTokenSignerCallback, tokenPath: 'test/token/path' },
    })
  })

  afterAll(async () => {
    jest.clearAllMocks()
    server.stop()
    // await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  let credOfferSession: CredentialOfferSession
  let uri: string
  let client: OpenID4VCIClient
  it('should create credential offer', async () => {
    expect(server.issuer).toBeDefined()
    uri = await vcIssuer.createCredentialOfferURI({
      grants: {
        authorization_code: {
          issuer_state: issuerState,
        },
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code': preAuthorizedCode,
          user_pin_required: true,
        },
      },
      credentials: ['UniversityDegree_JWT'],
      scheme: 'http',
    })
    expect(uri).toEqual(
      'http://localhost:3456/test?credential_offer=%7B%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22previously-created-state%22%7D%2C%22urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code%22%3A%7B%22pre-authorized_code%22%3A%22test_code%22%2C%22user_pin_required%22%3Atrue%7D%7D%2C%22credentials%22%3A%5B%22UniversityDegree_JWT%22%5D%2C%22credential_issuer%22%3A%22http%3A%2F%2Flocalhost%3A3456%2Ftest%22%7D'
    )
  })

  it('should create client from credential offer URI', async () => {
    client = await OpenID4VCIClient.fromURI({
      uri,
      flowType: AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW,
      kid: subjectDIDKey.didDocument.authentication[0],
      alg: 'ES256',
    })
    expect(client.credentialOffer).toEqual({
      baseUrl: 'http://localhost:3456/test',
      credential_offer: {
        credential_issuer: 'http://localhost:3456/test',
        credentials: ['UniversityDegree_JWT'],
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
      original_credential_offer: {
        credential_issuer: 'http://localhost:3456/test',
        credentials: ['UniversityDegree_JWT'],
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
      scheme: 'http',
      supportedFlows: [AuthzFlowType.AUTHORIZATION_CODE_FLOW, AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW],
      version: 1011,
    })
    expect(client.getIssuer()).toEqual(ISSUER_URL)
    expect(client.version()).toEqual(OpenId4VCIVersion.VER_1_0_11)
  })

  it('should retrieve server metadata', async () => {
    await expect(client.retrieveServerMetadata()).resolves.toEqual({
      credential_endpoint: 'http://localhost:3456/test/credential-endpoint',
      issuer: 'http://localhost:3456/test',
      issuerMetadata: {
        credential_endpoint: 'http://localhost:3456/test/credential-endpoint',
        credential_issuer: 'http://localhost:3456/test',
        credentials_supported: [
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
        display: [
          {
            locale: 'en-US',
            name: 'example issuer',
          },
        ],
        token_endpoint: 'http://localhost:3456/test/test/token/path',
      },
      token_endpoint: 'http://localhost:3456/test/test/token/path',
    })
  })
  it('should get state on server side', async () => {
    const preAuthCode =
      client.credentialOffer.credential_offer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code']
    expect(preAuthCode).toBeDefined()

    if (preAuthCode) {
      credOfferSession = await vcIssuer.credentialOfferSessions.getAsserted(preAuthCode)
    }
    expect(credOfferSession).toBeDefined()
  })

  it('should acquire access token', async () => {
    accessToken = await client.acquireAccessToken({ pin: credOfferSession.userPin })
    expect(accessToken).toBeDefined()
  })
  it('should issue credential', async () => {
    async function proofOfPossessionCallbackFunction(args: Jwt, kid?: string): Promise<string> {
      return await new jose.SignJWT({ ...args.payload })
        .setProtectedHeader({ ...args.header })
        .setIssuedAt(+new Date())
        .setIssuer(kid!)
        .setAudience(args.payload.aud!)
        .setExpirationTime('2h')
        .sign(subjectKeypair.privateKey)
    }

    const credentialResponse = await client.acquireCredentials({
      credentialTypes: ['VerifiableCredential'],
      format: 'jwt_vc_json',
      proofCallbacks: { signCallback: proofOfPossessionCallbackFunction },
    })
    expect(credentialResponse).toMatchObject({
      c_nonce_expires_in: 90000,
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        credentialSubject: {},
        issuer: 'did:key:test',
        proof: {
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
