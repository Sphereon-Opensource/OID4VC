import {
  AssertedUniformCredentialOffer,
  CNonceState,
  CredentialDataSupplierInput,
  CredentialSupplierConfig,
  JwtVerifyResult,
  OID4VCICredentialFormat,
  UniformCredentialRequest,
  VCI_LOGGERS,
} from '@sphereon/oid4vci-common'
import {
  CompactSdJwtVc,
  ICredential,
  LogMethod,
  SdJwtDecodedVerifiableCredentialPayload,
  SdJwtDisclosureFrame,
  W3CVerifiableCredential,
} from '@sphereon/ssi-types'

export type CredentialSignerCallback<T extends object> = (opts: {
  credentialRequest: UniformCredentialRequest
  credential: CredentialIssuanceInput
  format?: OID4VCICredentialFormat
  /**
   * We use object since we don't want to expose the DID Document TS type to too many interfaces.
   * An implementation that wants to look into the DIDDoc would have to do a cast in the signer callback implementation
   */
  jwtVerifyResult: JwtVerifyResult<T>
}) => Promise<W3CVerifiableCredential | CompactSdJwtVc>

export interface CredentialDataSupplierArgs extends CNonceState {
  credentialRequest: UniformCredentialRequest
  credentialOffer: AssertedUniformCredentialOffer
  clientId?: string
  credentialSupplierConfig?: CredentialSupplierConfig
  credentialDataSupplierInput?: CredentialDataSupplierInput
}

export type CredentialIssuanceInput = ICredential | (SdJwtDecodedVerifiableCredentialPayload & { __disclosureFrame?: SdJwtDisclosureFrame })

export interface CredentialDataSupplierResult {
  credential: CredentialIssuanceInput
  format?: OID4VCICredentialFormat
  signCallback?: CredentialSignerCallback<any> // If the data supplier wants to actually sign directly
}

export type CredentialDataSupplier = (args: CredentialDataSupplierArgs) => Promise<CredentialDataSupplierResult>

export const LOG = VCI_LOGGERS.options('sphereon:oid4vci:issuer', { methods: [LogMethod.EVENT, LogMethod.DEBUG_PKG] }).get('sphereon:oid4vci:issuer')
