import * as v from 'valibot'

import { vJarmAuthResponseParams } from './v-jarm-auth-response-params.js'

export const vJarmDirectPostJwtParams = v.looseObject({
  ...v.omit(vJarmAuthResponseParams, ['iss', 'aud', 'exp']).entries,
  ...v.partial(v.pick(vJarmAuthResponseParams, ['iss', 'aud', 'exp'])).entries,

  vp_token: v.union([v.string(), v.array(v.pipe(v.string(), v.nonEmpty()))]),
  presentation_submission: v.unknown(),
  nonce: v.optional(v.string()),
})

export type JarmDirectPostJwtResponseParams = v.InferInput<typeof vJarmDirectPostJwtParams>

export const jarmAuthResponseDirectPostValidateParams = (input: {
  authRequestParams: { state?: string }
  authResponseParams: JarmDirectPostJwtResponseParams
}) => {
  const { authRequestParams, authResponseParams } = input

  // 2. The client obtains the state parameter from the JWT and checks its binding to the user agent. If the check fails, the client MUST abort processing and refuse the response.
  if (authRequestParams.state !== authResponseParams.state) {
    throw new Error(`State missmatch between auth request '${authRequestParams.state}' and the jarm-auth-response.`)
  }
}
