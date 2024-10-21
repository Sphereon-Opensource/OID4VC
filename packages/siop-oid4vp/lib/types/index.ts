import { VCI_LOGGERS } from '@sphereon/oid4vc-common'
import { ISimpleLogger, LogMethod } from '@sphereon/ssi-types'

import SIOPErrors from './Errors'

export const LOG: ISimpleLogger<string> = VCI_LOGGERS.options('sphereon:siop-oid4vp', { methods: [LogMethod.EVENT, LogMethod.DEBUG_PKG] }).get(
  'sphereon:siop-oid4vp',
)

export { SIOPErrors }
export * from './JWT.types'
export * from './SIOP.types'
export * from './Events'
export * from './SessionManager'
export * from './VpJwtIssuer'
export * from './VpJwtVerifier'
