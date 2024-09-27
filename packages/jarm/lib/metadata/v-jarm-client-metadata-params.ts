import * as v from 'valibot';

const vJarmClientMetadataParamsBase = v.object({
  authorization_signed_response_alg: v.pipe(
    v.optional(v.string(), 'RS256'),
    v.description(
      'JWA. If this is specified, the response will be signed using JWS and the configured algorithm. The algorithm none is not allowed.'
    )
  ),

  authorization_encrypted_response_alg: v.optional(v.never()),
  authorization_encrypted_response_enc: v.optional(v.never()),
});

/**
 * Clients may register their public encryption keys using the jwks_uri or jwks metadata parameters.
 */
export const vJarmClientMetadataParams = v.union([
  v.object({
    ...vJarmClientMetadataParamsBase.entries,
  }),
  v.object({
    ...vJarmClientMetadataParamsBase.entries,

    authorization_encrypted_response_alg: v.pipe(
      v.string(),
      v.description(
        'JWE alg algorithm JWA. If both signing and encryption are requested, the response will be signed then encrypted with the provided algorithm.'
      )
    ),

    authorization_encrypted_response_enc: v.pipe(
      v.optional(v.string(), 'A128CBC-HS256'),
      v.description(
        'JWE enc algorithm JWA. If both signing and encryption are requested, the response will be signed then encrypted with the provided algorithm.'
      )
    ),
  }),
]);

export type JarmClientMetadataParams = v.InferInput<
  typeof vJarmClientMetadataParams
>;
