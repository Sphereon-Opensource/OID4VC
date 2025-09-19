import { JwtIssuer } from '@sphereon/oid4vc-common'
import { ClaimPayloadCommonOpts, RequestObjectPayloadOpts } from '../authorization-request'
import { ObjectBy, CreateJwtCallback } from '../types'

export interface RequestObjectOpts<CT extends ClaimPayloadCommonOpts> extends ObjectBy {
  payload?: RequestObjectPayloadOpts<CT> // for pass by value
  createJwtCallback: CreateJwtCallback
  jwtIssuer: JwtIssuer
}
