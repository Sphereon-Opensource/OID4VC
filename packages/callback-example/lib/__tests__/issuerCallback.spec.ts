import { KeyObject } from 'crypto'

import { CredentialRequestClient, CredentialRequestClientBuilderV1_0_09, ProofOfPossessionBuilder } from '@sphereon/openid4vci-client'
import {
  Alg,
  CredentialFormatEnum,
  CredentialSupported,
  Display,
  IssuerCredentialSubjectDisplay,
  Jwt,
  ProofOfPossession,
  Typ,
} from '@sphereon/openid4vci-common'
import { CredentialSupportedBuilderV1_11, VcIssuer, VcIssuerBuilder } from '@sphereon/openid4vci-issuer'
import { MemoryCredentialOfferStateManager } from '@sphereon/openid4vci-issuer/dist/state-manager/MemoryCredentialOfferStateManager'
import { ICredential, IProofPurpose, IProofType, W3CVerifiableCredential } from '@sphereon/ssi-types'
import * as jose from 'jose'

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
describe('issuerCallback', () => {
  let vcIssuer: VcIssuer
  const state = 'existing-client'
  const clientId = 'sphereon:wallet'
  const preAuthorizedCode = 'pre_authorized_test_code'

  beforeAll(async () => {
    const credentialsSupported: CredentialSupported = new CredentialSupportedBuilderV1_11()
      .withCryptographicSuitesSupported('ES256K')
      .withCryptographicBindingMethod('did')
      //FIXME Here a CredentialFormatEnum is passed in, but later it is matched against a CredentialFormat
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
      clientId,
      'pre-authorized_code': preAuthorizedCode,
      createdOn: +new Date(),
      credentialOffer: {
        credential_issuer: 'did:key:test',
        credential_definition: {
          types: ['VerifiableCredential'],
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          credentialSubject: {},
        },
        grants: {
          authorization_code: { issuer_state: 'test_code' },
          'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'test_code', user_pin_required: true },
        },
      },
    })
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
      .withInMemoryCNonceState()
      .withJWTVerifyCallback(verifyCallbackFunction)
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
      .build()
  }, 30000)

  it('should issue a VC', async () => {
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
    //FIXME Use the same Enum to match format. It's actually using CredentialFormat and CredentialFormatEnum
    const credReqClient = CredentialRequestClientBuilderV1_0_09.fromURI({ uri: INITIATION_TEST_URI })
      .withCredentialEndpoint('https://oidc4vci.demo.spruceid.com/credential')
      .withFormat('jwt_vc_json')
      .withCredentialType('credentialType')
      .withToken('token')

    const jwt: Jwt = {
      header: { alg: Alg.ES256, kid: 'did:example:ebfeb1f712ebc6f1c276e12ec21/keys/1', typ: Typ['OPENID4VCI-PROOF+JWT'] },
      payload: { iss: 'sphereon:wallet', nonce: 'tZignsnFbp', jti: 'tZignsnFbp223', aud: IDENTIPROOF_ISSUER_URL },
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
    })
      .withClientId(clientId)
      .withKid(kid)
      .build()

    const credentialRequestClient = new CredentialRequestClient(credReqClient)
    const credentialRequest = await credentialRequestClient.createCredentialRequest({
      credentialType: ['VerifiableCredential'],
      format: 'jwt_vc_json',
      proofInput: proof,
    })
    expect(credentialRequest).toEqual({
      format: 'jwt_vc_json',
      proof: {
        jwt: expect.stringContaining(
          'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOmViZmViMWY3MTJlYmM2ZjFjMjc2ZTEyZWMyMS9rZXlzLzEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpl'
        ),
        proof_type: 'jwt',
      },
      type: ['VerifiableCredential'],
    })

    const credentialResponse = await vcIssuer.issueCredentialFromIssueRequest({
      issueCredentialRequest: credentialRequest,
      issuerState: state,
      issuerCallback: getIssuerCallback(credential, didKey.keyPairs, didKey.didDocument.verificationMethod[0].id),
    })

    expect(credentialResponse).toEqual({
      c_nonce: expect.any(String),
      c_nonce_expires_in: 90000,
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
