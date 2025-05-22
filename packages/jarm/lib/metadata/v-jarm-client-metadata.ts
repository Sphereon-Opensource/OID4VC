import * as v from 'valibot'

export const vJarmClientMetadataSign = v.object({
  authorization_signed_response_alg: v.pipe(
    v.optional(v.string()), // @default 'RS256'  This makes no sense with openid4vp if just encrypted can be specified
    v.description(
      'JWA. If this is specified, the response will be signed using JWS and the configured algorithm. The algorithm none is not allowed.',
    ),
  ),

  authorization_encrypted_response_alg: v.optional(v.never()),
  authorization_encrypted_response_enc: v.optional(v.never()),
})

export const vJarmClientMetadataEncrypt = v.object({
  authorization_signed_response_alg: v.optional(v.never()),
  authorization_encrypted_response_alg: v.pipe(
    v.string(),
    v.description(
      'JWE alg algorithm JWA. If both signing and encryption are requested, the response will be signed then encrypted with the provided algorithm.',
    ),
  ),

  authorization_encrypted_response_enc: v.pipe(
    v.optional(v.string(), 'A128CBC-HS256'),
    v.description(
      'JWE enc algorithm JWA. If both signing and encryption are requested, the response will be signed then encrypted with the provided algorithm.',
    ),
  ),
})

export const vJarmClientMetadataSignEncrypt = v.object({
  ...v.pick(vJarmClientMetadataSign, ['authorization_signed_response_alg']).entries,
  ...v.pick(vJarmClientMetadataEncrypt, ['authorization_encrypted_response_alg', 'authorization_encrypted_response_enc']).entries,
})

/**
 * Clients may register their public encryption keys using the jwks_uri or jwks metadata parameters.
 */
export const vJarmClientMetadata = v.union([vJarmClientMetadataSign, vJarmClientMetadataEncrypt, vJarmClientMetadataSignEncrypt])

export type JarmClientMetadata = v.InferInput<typeof vJarmClientMetadata>
