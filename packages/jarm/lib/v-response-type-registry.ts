import * as v from 'valibot'

export const oAuthResponseTypes = v.picklist(['code', 'token'])

// NOTE: MAKE SURE THAT THE RESPONSE TYPES ARE SORTED CORRECTLY
export const oAuthMRTEPResponseTypes = v.picklist(['none', 'id_token', 'code token', 'code id_token', 'id_token token', 'code id_token token'])

export const openid4vpResponseTypes = v.picklist(['vp_token', 'id_token vp_token'])

export const vTransformedResponseTypes = v.picklist([
  ...openid4vpResponseTypes.options,
  ...oAuthResponseTypes.options,
  ...oAuthMRTEPResponseTypes.options,
])

export const vResponseType = v.pipe(
  v.string(),
  v.transform((val) => val.split(' ').sort().join(' ')),
  vTransformedResponseTypes,
)

export type ResponseType = v.InferInput<typeof vTransformedResponseTypes>
export type ResponseTypeOut = v.InferOutput<typeof vTransformedResponseTypes>
