import * as didKeyDriver from '@digitalcredentials/did-method-key'
import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020'
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020'
import { securityLoader } from '@digitalcredentials/security-document-loader'
import vc from '@digitalcredentials/vc'
import { CredentialRequest } from '@sphereon/openid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'

export const generateDid = async () => {
  const didKD = didKeyDriver.driver()
  const { didDocument, keyPairs, methodFor } = await didKD.generate()
  return { didDocument, keyPairs, methodFor }
}

export const getIssuerCallback = (credential: ICredential) => {
  if (!credential) {
    throw new Error('A credential needs to be provided')
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  return async (_opts: { credentialRequest?: CredentialRequest; credential?: ICredential }): Promise<W3CVerifiableCredential> => {
    const documentLoader = securityLoader().build()
    const keyPair = await Ed25519VerificationKey2020.generate()
    const suite = new Ed25519Signature2020({ key: keyPair })
    suite.verificationMethod = (await generateDid()).didDocument.verificationMethod[0].id
    return await vc.issue({ credential, suite, documentLoader })
  }
}
