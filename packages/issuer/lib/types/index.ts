import {
  AssertedUniformCredentialOffer,
  CNonceState,
  CredentialDataSupplierInput,
  OID4VCICredentialFormat,
  UniformCredentialRequest,
} from '@sphereon/oid4vci-common'
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
  credentialDataSupplierInput?: CredentialDataSupplierInput
}

export interface CredentialDataSupplierResult {
  credential: ICredential
  format?: OID4VCICredentialFormat
  signCallback?: CredentialSignerCallback // If the data supplier wants to actually sign directly
}

export type CredentialDataSupplier = (args: CredentialDataSupplierArgs) => Promise<CredentialDataSupplierResult>
