import { AssertedUniformCredentialOffer, CNonceState, OID4VCICredentialFormat, UniformCredentialRequest } from '@sphereon/oid4vci-common'
import { ICredential, W3CVerifiableCredential } from '@sphereon/ssi-types'

export type CredentialSignerCallback = (opts: {
  credentialRequest: UniformCredentialRequest
  credential: ICredential
  format?: OID4VCICredentialFormat
}) => Promise<W3CVerifiableCredential>

export interface CredentialDataSupplierArgs extends CNonceState {
  credentialRequest: UniformCredentialRequest
  clientId?: string
  credentialOffer: AssertedUniformCredentialOffer
}

export interface CredentialDataSupplierResult {
  credential: ICredential
  format?: OID4VCICredentialFormat
  callback?: CredentialSignerCallback // If the data supplier wants to actually sign directly
}

export type CredentialDataSupplier = (args: CredentialDataSupplierArgs) => Promise<CredentialDataSupplierResult>
