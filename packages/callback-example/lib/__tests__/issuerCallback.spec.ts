import { KeyObject } from 'crypto'

import { CredentialRequestClient, CredentialRequestClientBuilder, ProofOfPossessionBuilder } from '@sphereon/oid4vci-client'
import {
  Alg,
  CNonceState,
  CredentialOfferJwtVcJsonLdAndLdpVcV1_0_11,
  CredentialSupported,
  IssuerCredentialSubjectDisplay,
  Jwt,
  OpenId4VCIVersion,
  ProofOfPossession,
} from '@sphereon/oid4vci-common'
import { CredentialOfferSession } from '@sphereon/oid4vci-common/dist'
import { CredentialSupportedBuilderV1_11, VcIssuer, VcIssuerBuilder } from '@sphereon/oid4vci-issuer'
import { CredentialDataSupplierResult } from '@sphereon/oid4vci-issuer/dist/types'
import { ICredential, IProofPurpose, IProofType, W3CVerifiableCredential } from '@sphereon/ssi-types'
import * as jose from 'jose'

import { MemoryStates } from '../../../issuer/lib/state-manager'
import { generateDid, getIssuerCallback, verifyCredential } from '../IssuerCallback'

const INITIATION_TEST_URI =
  'openid-initiate-issuance://?credential_type=OpenBadgeCredential&issuer=https%3A%2F%2Fjff%2Ewalt%2Eid%2Fissuer-api%2Foidc%2F&pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE&user_pin_required=false'
const IDENTIPROOF_ISSUER_URL = 'https://example.com/credential'
const kid = 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1'
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
    .setIssuedAt(+new Date())
    .setIssuer(kid)
    .setAudience(args.payload.aud)
    .setExpirationTime('2h')
    .sign(keypair.privateKey)
}

async function verifyCallbackFunction(args: { jwt: string; kid?: string }): Promise<Jwt> {
  const result = await jose.jwtVerify(args.jwt, keypair.publicKey)
  return {
    header: result.protectedHeader,
    payload: result.payload,
  } as Jwt
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
  let vcIssuer: VcIssuer
  const state = 'existing-state'
  const clientId = 'sphereon:wallet'

  beforeAll(async () => {
    const credentialsSupported: CredentialSupported = new CredentialSupportedBuilderV1_11()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      .withFormat('jwt_vc_json')
      .withTypes('VerifiableCredential')
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
    await stateManager.set('existing-state', {
      issuerState: 'existing-state',
      clientId,
      createdAt: +new Date(),
      userPin: '123456',
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

    const nonces = new MemoryStates<CNonceState>()
    nonces.set('test_value', { cNonce: 'test_value', createdAt: +new Date(), issuerState: 'existing-state' })
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
          }) as Promise<CredentialDataSupplierResult>
      )
      .withCredentialSignerCallback((opts) =>
        Promise.resolve({
          ...opts.credential,
          proof: {
            type: IProofType.JwtProof2020,
            jwt: 'ye.ye.ye',
            created: new Date().toISOString(),
            proofPurpose: IProofPurpose.assertionMethod,
            verificationMethod: 'sdfsdfasdfasdfasdfasdfassdfasdf',
          },
        })
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
    const vc = await getIssuerCallback(credential, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id)({})
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
      expect.objectContaining({ verified: true })
    )
  })
  it('Should pass requesting a verifiable credential using the client', async () => {
    const credReqClient = (await CredentialRequestClientBuilder.fromURI({ uri: INITIATION_TEST_URI }))
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withToken('token')

    const jwt: Jwt = {
      header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: 'openid4vci-proof+jwt' },
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
      version: OpenId4VCIVersion.VER_1_0_11,
    })
      .withClientId(clientId)
      .withKid(kid)
      .build()

    const credentialRequestClient = new CredentialRequestClient(credReqClient)

    // FIXME: The initiation is v8, but the test expects a v9 credential request.
    // it will now fail because of a check if we don't change the version.
    // the QR should be changed, or the output check should be changed
    credentialRequestClient.credentialRequestOpts.version = OpenId4VCIVersion.VER_1_0_09

    const credentialRequest = await credentialRequestClient.createCredentialRequest({
      requestInput: {
        types: ['VerifiableCredential'],
        format: 'jwt_vc_json',
      },
      proofInput: proof,
    })
    expect(credentialRequest).toEqual({
      format: 'jwt_vc_json',
      types: ['VerifiableCredential'],
      proof: {
        jwt: expect.stringContaining('eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFj'),
        proof_type: 'jwt',
      },
    })

    const credentialResponse = await vcIssuer.issueCredential({
      credentialRequest: credentialRequest,
      credential,
      responseCNonce: state,
      credentialSignerCallback: getIssuerCallback(credential, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id),
    })

    expect(credentialResponse).toEqual({
      c_nonce: expect.any(String),
      c_nonce_expires_in: 300000,
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1', 'https://w3id.org/security/suites/ed25519-2020/v1'],
        credentialSubject: {},
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
      format: 'jwt_vc_json',
    })

    await expect(
      verifyCredential(credentialResponse.credential as W3CVerifiableCredential, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id)
    ).resolves.toEqual(expect.objectContaining({ verified: true }))
  })
})
