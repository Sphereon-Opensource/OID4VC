import * as v from 'valibot'

/**
 * Authorization servers SHOULD publish the supported algorithms for signing and encrypting the JWT of an authorization response by utilizing OAuth 2.0 Authorization Server Metadata [RFC8414] parameters.
 */
export const vJarmServerMetadata = v.object({
  authorization_signing_alg_values_supported: v.pipe(
    v.array(v.string()),
    v.description(
      'JSON array containing a list of the JWS [RFC7515] signing algorithms (alg values) JWA [RFC7518] supported by the authorization endpoint to sign the response.',
    ),
  ),

  authorization_encryption_alg_values_supported: v.pipe(
    v.array(v.string()),
    v.description(
      'JSON array containing a list of the JWE [RFC7516] encryption algorithms (alg values) JWA [RFC7518] supported by the authorization endpoint to encrypt the response.',
    ),
  ),

  authorization_encryption_enc_values_supported: v.pipe(
    v.array(v.string()),
    v.description(
      'JSON array containing a list of the JWE [RFC7516] encryption algorithms (enc values) JWA [RFC7518] supported by the authorization endpoint to encrypt the response.',
    ),
  ),
})

export type JarmServerMetadata = v.InferInput<typeof vJarmServerMetadata>
