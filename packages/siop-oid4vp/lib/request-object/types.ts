import { ClaimPayloadCommonOpts, RequestObjectPayloadOpts } from '../authorization-request'
import { ObjectBy } from '../types'
import { CreateJwtCallback, JwtIssuer } from '../types/JwtIssuer'

export interface RequestObjectOpts<CT extends ClaimPayloadCommonOpts> extends ObjectBy {
  payload?: RequestObjectPayloadOpts<CT> // for pass by value
  createJwtCallback: CreateJwtCallback
  jwtIssuer: JwtIssuer
}
