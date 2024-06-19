import { VCI_LOGGERS } from '@sphereon/oid4vci-common'
import { ISimpleLogger } from '@sphereon/ssi-types'

export const LOG: ISimpleLogger<string | unknown> = VCI_LOGGERS.get('sphereon:oid4vci:issuer')

export * from './builder'
export * from './functions'
export * from './VcIssuer'
export * from './state-manager'
export * from './tokens'
export * from './types'
