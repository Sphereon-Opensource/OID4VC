import { Ed25519Signature2020 } from '@digitalcredentials/ed25519-signature-2020'
import { Ed25519VerificationKey2020 } from '@digitalcredentials/ed25519-verification-key-2020'
import vc, { defaultDocumentLoader } from '@digitalcredentials/vc'

import { CredentialRequest } from '@sphereon/openid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'

export const credentialCallback = async (opts: {
  credentialRequest?: CredentialRequest
  credential?: ICredential
}): Promise<W3CVerifiableCredential> => {
  const keyPair = await Ed25519VerificationKey2020.generate()
  const suite = new Ed25519Signature2020({ key: keyPair })
  const credential = opts.credential
  return await vc.issue({ credential, suite, defaultDocumentLoader })
}
