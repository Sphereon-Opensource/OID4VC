import { CreateJwtCallback as CreateJwtCallbackBase, JwtIssuanceContextBase, JwtIssuer } from '@sphereon/oid4vci-common'

import { AuthorizationResponseOpts } from '../authorization-response'

interface RequestObjectContext extends JwtIssuanceContextBase {
  type: 'request-object'
}

interface IdTokenContext extends JwtIssuanceContextBase {
  type: 'id-token'
  authorizationResponseOpts: AuthorizationResponseOpts
}

export type JwtIssuanceContext = RequestObjectContext | IdTokenContext

export type JwtIssuerWithContext = JwtIssuer & JwtIssuanceContext

export type CreateJwtCallback = CreateJwtCallbackBase<JwtIssuerWithContext>
