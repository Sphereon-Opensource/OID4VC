import * as v from 'valibot'

import type { ResponseTypeOut } from './v-response-type-registry.js'

export const vJarmResponseMode = v.picklist(['jwt', 'query.jwt', 'fragment.jwt', 'form_post.jwt'])
export type JarmResponseMode = v.InferInput<typeof vJarmResponseMode>

export const vOpenid4vpResponseMode = v.picklist(['direct_post'])
export type Openid4vpResponseMode = v.InferInput<typeof vOpenid4vpResponseMode>

/**
 *  * 'direct_post.jwt' The response is send as HTTP POST request using the application/x-www-form-urlencoded content type. The body contains a single parameter response which is the JWT encoded Response as defined in JARM 4.1
 */
export const vOpenid4vpJarmResponseMode = v.picklist(['direct_post.jwt'])
export type Openid4vpJarmResponseMode = v.InferInput<typeof vOpenid4vpJarmResponseMode>

/**
 *  The use of this parameter is NOT RECOMMENDED when the Response Mode that would be requested is the default mode specified for the Response Type.
 *  * 'query' In this mode, Authorization Response parameters are encoded in the query string added to the redirect_uri when redirecting back to the Client.
 *  * 'fragment' In this mode, Authorization Response parameters are encoded in the fragment added to the redirect_uri when redirecting back to the Client.
 *  * 'direct_post' the Authorization Response is send to an endpoint controlled by the Verifier via an HTTP POST request.
 */
export const vResponseMode = v.pipe(
  v.picklist(['query', 'fragment', ...vOpenid4vpResponseMode.options, ...vJarmResponseMode.options, ...vOpenid4vpJarmResponseMode.options]),
  v.description('Informs the Authorization Server of the mechanism to be used for returning parameters from the Authorization Endpoint.'),
)
export type ResponseMode = v.InferInput<typeof vResponseMode>

const getDisAllowedResponseModes = (input: { response_type: ResponseTypeOut }): [ResponseMode, ...ResponseMode[]] | undefined => {
  const { response_type } = input

  switch (response_type) {
    case 'code token':
      return ['query']
    case 'code id_token':
      return ['query']
    case 'id_token token':
      return ['query']
    case 'code id_token token':
      return ['query']
  }
  return undefined
}

export const getDefaultResponseMode = (input: { response_type: ResponseTypeOut }): 'query' | 'fragment' => {
  const { response_type } = input

  switch (response_type) {
    case 'code':
    case 'none':
      return 'query'
    case 'token':
    case 'id_token':
    case 'code token':
    case 'code id_token':
    case 'id_token token':
    case 'code id_token token':
    case 'vp_token':
    case 'id_token vp_token':
      return 'fragment'
  }
}

export const getJarmDefaultResponseMode = (input: { response_type: ResponseTypeOut }): 'query.jwt' | 'fragment.jwt' => {
  const responseMode = getDefaultResponseMode(input)

  switch (responseMode) {
    case 'query':
      return 'query.jwt'
    case 'fragment':
      return 'fragment.jwt'
  }
}

export const validateResponseMode = (input: { response_type: ResponseTypeOut; response_mode: ResponseMode }) => {
  const disallowedResponseModes = getDisAllowedResponseModes(input)

  if (disallowedResponseModes?.includes(input.response_mode)) {
    throw new Error(`Response_type '${input.response_type}' is not compatible with response_mode '${input.response_mode}'.`)
  }
}
