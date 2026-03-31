import { VCI_LOG_COMMON } from '../index'
import { IssuerMetadata, SignedMetadataVerifyCallback } from '../types'

/**
 * Process the signed_metadata JWT from issuer metadata.
 *
 * Per OID4VCI spec, signed_metadata is a signed JWT containing Credential Issuer
 * metadata parameters as claims. When present and verified, the signed claims
 * take precedence over unsigned metadata fields.
 *
 * @param opts.metadata - The fetched issuer metadata (may contain signed_metadata)
 * @param opts.issuer - The credential_issuer URL for JWT validation
 * @param opts.signedMetadataVerifyCallback - Callback to verify and decode the signed JWT
 * @returns The metadata with signed claims merged in (signed claims override unsigned)
 */
export async function processSignedMetadata<T extends IssuerMetadata>(opts: {
  metadata: T
  issuer: string
  signedMetadataVerifyCallback?: SignedMetadataVerifyCallback
}): Promise<T> {
  const { metadata, issuer, signedMetadataVerifyCallback } = opts

  if (!metadata.signed_metadata) {
    return metadata
  }

  if (!signedMetadataVerifyCallback) {
    VCI_LOG_COMMON.warning(
      `Issuer ${issuer} provides signed_metadata but no signedMetadataVerifyCallback was provided. Signed metadata will not be verified or applied.`,
    )
    return metadata
  }

  const result = await signedMetadataVerifyCallback({
    signedMetadata: metadata.signed_metadata,
    issuer,
  })

  if (!result.verified) {
    throw Error(`Signed metadata verification failed for issuer ${issuer}`)
  }

  VCI_LOG_COMMON.info(`Signed metadata verified for issuer ${issuer}, applying signed claims`)

  // Merge signed claims into metadata. Signed claims override unsigned fields.
  // Exclude JWT-specific claims that are not metadata parameters.
  const { iss: _iss, iat: _iat, exp: _exp, nbf: _nbf, jti: _jti, aud: _aud, sub: _sub, ...metadataClaims } = result.metadata
  return { ...metadata, ...metadataClaims } as T
}
