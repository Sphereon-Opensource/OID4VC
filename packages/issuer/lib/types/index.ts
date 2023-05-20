import { CredentialRequestV1_0_11 } from '@sphereon/oid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'

export type CredentialIssuerCallback = (opts: {
  credentialRequest?: CredentialRequestV1_0_11
  credential?: ICredential
}) => Promise<W3CVerifiableCredential>
