import { VCI_LOGGERS } from '@sphereon/oid4vci-common'
import { ISimpleLogger } from '@sphereon/ssi-types'

export const LOG: ISimpleLogger<string> = VCI_LOGGERS.get('sphereon:oid4vci:client')

export * from './AccessTokenClient'
export * from './AuthorizationCodeClient'
export * from './CredentialRequestClient'
export * from './CredentialOfferClient'
export * from './CredentialOfferClientV1_0_15'
export * from './CredentialRequestClientBuilder'
export * from './CredentialRequestClientBuilderV1_0_15'
export * from './functions'
export * from './MetadataClient'
export * from './MetadataClientV1_0_15'
export * from './OpenID4VCIClient'
export * from './OpenID4VCIClientV1_0_15'
export * from './ProofOfPossessionBuilder'
