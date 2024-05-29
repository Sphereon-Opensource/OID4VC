import * as didKeyDriver from '@digitalcredentials/did-method-key'
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020'
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020'
import { securityLoader } from '@digitalcredentials/security-document-loader'
import vc from '@digitalcredentials/vc'
import { CredentialRequest, CredentialRequestV1_0_11 } from '@sphereon/oid4vci-common'
import { CredentialIssuanceInput } from '@sphereon/oid4vci-issuer'
import { CompactSdJwtVc, W3CVerifiableCredential } from '@sphereon/ssi-types'

// Example on how to generate a did:key to issue a verifiable credential
export const generateDid = async () => {
  const didKD = didKeyDriver.driver()
  const { didDocument, keyPairs, methodFor } = await didKD.generate()
  return { didDocument, keyPairs, methodFor }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const getIssuerCallbackV1_0_11 = (credential: CredentialIssuanceInput, keyPair: any, verificationMethod: string) => {
  if (!credential) {
    throw new Error('A credential needs to be provided')
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return async (_opts: {
    credentialRequest?: CredentialRequestV1_0_11
    credential?: CredentialIssuanceInput
  }): Promise<W3CVerifiableCredential | CompactSdJwtVc> => {
    const documentLoader = securityLoader().build()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const verificationKey: any = Array.from(keyPair.values())[0]
    const keys = await Ed25519VerificationKey2020.from({ ...verificationKey })
    const suite = new Ed25519Signature2020({ key: keys })
    suite.verificationMethod = verificationMethod
    return await vc.issue({ credential, suite, documentLoader })
  }
}

export const getIssuerCallbackV1_0_13 = (
  credential: CredentialIssuanceInput,
  credentialRequest: CredentialRequest,
  keyPair: any,
  verificationMethod: string,
) => {
  if (!credential) {
    throw new Error('A credential needs to be provided')
  }

  return async (_opts: {
    credentialRequest: CredentialRequest
    credential: CredentialIssuanceInput
    format?: string
    jwtVerifyResult: any // Adjust type if necessary
  }): Promise<W3CVerifiableCredential | CompactSdJwtVc> => {
    const documentLoader = securityLoader().build()
    const verificationKey: any = Array.from(keyPair.values())[0]
    const keys = await Ed25519VerificationKey2020.from({ ...verificationKey })
    const suite = new Ed25519Signature2020({ key: keys })
    suite.verificationMethod = verificationMethod
    return await vc.issue({ credential, suite, documentLoader })
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const verifyCredential = async (credential: W3CVerifiableCredential, keyPair: any, verificationMethod: string): Promise<any> => {
  const documentLoader = securityLoader().build()
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const verificationKey: any = Array.from(keyPair.values())[0]
  const keys = await Ed25519VerificationKey2020.from({ ...verificationKey })
  const suite = new Ed25519Signature2020({ key: keys })
  suite.verificationMethod = verificationMethod
  return await vc.verifyCredential({ credential, suite, documentLoader })
}
