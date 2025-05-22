import * as v from 'valibot'

import { vJarmResponseMode, vOpenid4vpJarmResponseMode } from '../v-response-mode-registry'
import { vResponseType } from '../v-response-type-registry'

import type { JarmAuthResponseParams } from './v-jarm-auth-response-params'
import type { JarmDirectPostJwtResponseParams } from './v-jarm-direct-post-jwt-auth-response-params'

export const vAuthRequestParams = v.looseObject({
  state: v.optional(v.string()),
  response_mode: v.optional(v.union([vJarmResponseMode, vOpenid4vpJarmResponseMode])),
  client_id: v.string(),
  response_type: vResponseType,
  client_metadata: v.looseObject({
    jwks: v.optional(
      v.object({
        keys: v.array(v.looseObject({ kid: v.optional(v.string()), kty: v.string() })),
      }),
    ),
    jwks_uri: v.optional(v.string()),
  }),
})

export type AuthRequestParams = v.InferInput<typeof vAuthRequestParams>

export const vOAuthAuthRequestGetParamsOut = v.object({
  authRequestParams: vAuthRequestParams,
})

export type OAuthAuthRequestGetParamsOut = v.InferOutput<typeof vOAuthAuthRequestGetParamsOut>

export interface JarmDirectPostJwtAuthResponseValidationContext {
  openid4vp: {
    authRequest: {
      getParams: (input: JarmAuthResponseParams | JarmDirectPostJwtResponseParams) => Promise<OAuthAuthRequestGetParamsOut>
    }
  }
  jwe: {
    decryptCompact: (input: { jwe: string; jwk: { kid: string } }) => Promise<{ plaintext: string }>
  }
}
