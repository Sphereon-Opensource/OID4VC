import { KeyObject } from 'crypto'

import { CredentialRequestClientBuilder, ProofOfPossessionBuilder } from '@sphereon/oid4vci-client'
import {
  Alg,
  CNonceState,
  CredentialConfigurationSupportedV1_0_13,
  CredentialIssuerMetadataV1_0_13,
  CredentialRequest,
  IssuerCredentialSubjectDisplay,
  IssueStatus,
  Jwt,
  JwtVerifyResult,
  OpenId4VCIVersion,
  ProofOfPossession,
} from '@sphereon/oid4vci-common'
import { CredentialOfferSession } from '@sphereon/oid4vci-common/dist'
import { CredentialSupportedBuilderV1_13, VcIssuer, VcIssuerBuilder } from '@sphereon/oid4vci-issuer'
import { MemoryStates } from '@sphereon/oid4vci-issuer'
import { CredentialDataSupplierResult } from '@sphereon/oid4vci-issuer/dist/types'
import { ICredential, IProofPurpose, IProofType, W3CVerifiableCredential } from '@sphereon/ssi-types'
import { DIDDocument } from 'did-resolver'
import * as jose from 'jose'
import { v4 } from 'uuid'

import { generateDid, getIssuerCallbackV1_0_11, getIssuerCallbackV1_0_13, verifyCredential } from '../IssuerCallback'

const INITIATION_TEST_URI =
  'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credential_configuration_ids%22:%5B%22UniversityDegreeCredential%22%5D,%22grants%22:%7B%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:%7B%22pre-authorized_code%22:%22oaKazRN8I0IbtZ0C7JuMn5%22,%22tx_code%22:%7B%22input_mode%22:%22text%22,%22description%22:%22Please%20enter%20the%20serial%20number%20of%20your%20physical%20drivers%20license%22%7D%7D%7D%7D'
const IDENTIPROOF_ISSUER_URL = 'https://example.com/credential'
const kid = 'did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1'
let keypair: KeyPair // Proof of Possession JWT
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let didKey: { didDocument: any; keyPairs: any; methodFor: any } // Json LD VC issuance
async function proofOfPossessionCallbackFunction(args: Jwt, kid?: string): Promise<string> {
  if (!args.payload.aud) {
    throw Error('aud required')
  } else if (!kid) {
    throw Error('kid required')
  }
  return await new jose.SignJWT({ ...args.payload })
    .setProtectedHeader({ ...args.header })
    .setIssuedAt(args.payload.iat ?? Math.round(+new Date() / 1000))
    .setIssuer(kid)
    .setAudience(args.payload.aud)
    .setExpirationTime('2h')
    .sign(keypair.privateKey)
}

async function verifyCallbackFunction(args: { jwt: string; kid?: string }): Promise<JwtVerifyResult<DIDDocument>> {
  const result = await jose.jwtVerify(args.jwt, keypair.publicKey)
  const kid = result.protectedHeader.kid ?? args.kid
  const did = kid!.split('#')[0]
  const didDocument: DIDDocument = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
  }
  const alg = result.protectedHeader.alg
  return {
    alg,
    kid,
    did,
    didDocument,
    jwt: {
      header: result.protectedHeader,
      payload: result.payload,
    },
  }
}

interface KeyPair {
  publicKey: KeyObject
  privateKey: KeyObject
}

beforeAll(async () => {
  const { privateKey, publicKey } = await jose.generateKeyPair('ES256')
  keypair = { publicKey: publicKey as KeyObject, privateKey: privateKey as KeyObject }
  didKey = await generateDid()
}, 30000)

afterAll(async () => {
  await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
})
describe('issuerCallback', () => {
  let vcIssuer: VcIssuer<DIDDocument>
  const state = 'existing-state'
  const clientId = 'sphereon:wallet'

  beforeAll(async () => {
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
    const stateManager = new MemoryStates<CredentialOfferSession>()
    await stateManager.set('existing-state', {
      issuerState: 'existing-state',
      clientId,
      createdAt: +new Date(),
      lastUpdatedAt: +new Date(),
      status: IssueStatus.OFFER_CREATED,
      notification_id: v4(),
      userPin: '123456',
      credentialOffer: {
        credential_offer: {
          credential_issuer: 'did:key:test',
          credentials: [
            {
              format: 'ldp_vc',
              credential_definition: {
                types: ['VerifiableCredential'],
                '@context': ['https://www.w3.org/2018/credentials/v1'],
                credentialSubject: {},
              },
            },
          ],
          grants: {
            authorization_code: { issuer_state: 'test_code' },
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
              'pre-authorized_code': 'test_code',
              user_pin_required: true,
            },
          },
        },
      },
    })

    const nonces = new MemoryStates<CNonceState>()
    await nonces.set('test_value', { cNonce: 'test_value', createdAt: +new Date(), issuerState: 'existing-state' })
    vcIssuer = new VcIssuerBuilder<DIDDocument>()
      .withAuthorizationServers('https://authorization-server')
      .withCredentialEndpoint('https://credential-endpoint')
      .withCredentialIssuer(IDENTIPROOF_ISSUER_URL)
      .withIssuerDisplay({
        name: 'example issuer',
        locale: 'en-US',
      })
      .withCredentialConfigurationsSupported(credentialsSupported)
      .withCredentialOfferStateManager(stateManager)
      .withCNonceStateManager(nonces)
      .withJWTVerifyCallback(verifyCallbackFunction)
      .withCredentialDataSupplier(
        () =>
          Promise.resolve({
            credential: {
              '@context': ['https://www.w3.org/2018/credentials/v1'],
              type: ['VerifiableCredential'],
              issuer: 'did:key:test',
              issuanceDate: new Date().toISOString(),
              credentialSubject: {},
            },
            format: 'ldp_vc',
          }) as Promise<CredentialDataSupplierResult>,
      )
      .withCredentialSignerCallback((opts) =>
        Promise.resolve({
          ...(opts.credential as ICredential),
          proof: {
            type: IProofType.JwtProof2020,
            jwt: 'ye.ye.ye',
            created: new Date().toISOString(),
            proofPurpose: IProofPurpose.assertionMethod,
            verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf',
          },
        }),
      )
      .build()
  }, 30000)

  afterAll(async () => {
    await new Promise((resolve) => setTimeout((v: void) => resolve(v), 500))
  })

  it('should add a proof to a credential', async () => {
    const credential: ICredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: didKey.didDocument.id,
      credentialSubject: {},
      issuanceDate: new Date().toISOString(),
    }
    const vc = await getIssuerCallbackV1_0_11(credential, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id)({})
    expect(vc).toEqual({
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
      credentialSubject: {},
      issuanceDate: expect.any(String),
      issuer: expect.stringContaining('did:key:'),
      proof: {
        created: expect.any(String),
        proofPurpose: 'assertionMethod',
        proofValue: expect.any(String),
        type: 'Ed25519Signature2020',
        verificationMethod: expect.any(String),
      },
      type: ['VerifiableCredential'],
    })
    await expect(verifyCredential(vc, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id)).resolves.toEqual(
      expect.objectContaining({ verified: true }),
    )
  })

  it('Should pass requesting a verifiable credential using the client', async () => {
    const credReqClient = (await CredentialRequestClientBuilder.fromURI({ uri: INITIATION_TEST_URI }))
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withCredentialEndpointFromMetadata({
        credential_configurations_supported: { VeriCred: { format: 'jwt_vc_json' } },
      } as unknown as CredentialIssuerMetadataV1_0_13)
      .withFormat('jwt_vc_json')
      .withCredentialIdentifier('VeriCred')
      .withToken('token')

    const jwt: Jwt = {
      header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21#keys-1', typ: 'openid4vci-proof+jwt' },
      payload: { iss: 'sphereon:wallet', nonce: 'test_value', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL },
    }

    const credential: ICredential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      issuer: didKey.didDocument.id,
      credentialSubject: {},
      issuanceDate: new Date().toISOString(),
    }

    const proof: ProofOfPossession = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: {
        signCallback: proofOfPossessionCallbackFunction,
      },
      version: OpenId4VCIVersion.VER_1_0_13,
    })
      .withClientId(clientId)
      .withKid(kid)
      .build()

    const credentialRequestClient = credReqClient.build()
    const credentialRequest: CredentialRequest = await credentialRequestClient.createCredentialRequest({
      credentialIdentifier: 'VerifiableCredential',
      // format: 'jwt_vc_json',
      proofInput: proof,
      version: OpenId4VCIVersion.VER_1_0_13,
    })

    expect(credentialRequest).toEqual({
      // format: 'jwt_vc_json',
      proof: {
        jwt: expect.stringContaining('eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFj'),
        proof_type: 'JWT',
      },
      credential_identifier: 'VerifiableCredential',
    })

    const credentialResponse = await vcIssuer.issueCredential({
      credentialRequest: credentialRequest,
      credential,
      responseCNonce: state,
      credentialSignerCallback: getIssuerCallbackV1_0_13(credential, credentialRequest, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id),
    })

    expect(credentialResponse).toEqual({
      c_nonce: expect.any(String),
      notification_id: expect.any(String),
      c_nonce_expires_in: 300,
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
        credentialSubject: {
          id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
        },
        issuanceDate: expect.any(String),
        issuer: didKey.didDocument.id,
        proof: {
          created: expect.any(String),
          proofPurpose: 'assertionMethod',
          proofValue: expect.any(String),
          type: 'Ed25519Signature2020',
          verificationMethod: expect.stringContaining('did:key:'),
        },
        type: ['VerifiableCredential'],
      },
      // format: 'jwt_vc_json',
    })

    await expect(
      verifyCredential(credentialResponse.credential as W3CVerifiableCredential, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id),
    ).resolves.toEqual(expect.objectContaining({ verified: true }))
  })
})
