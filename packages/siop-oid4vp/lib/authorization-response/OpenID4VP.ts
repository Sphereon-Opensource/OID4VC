import {
  CompactSdJwtVc,
  CredentialMapper,
  HasherSync,
  IVerifiablePresentation,
  W3CVerifiablePresentation,
  WrappedMdocCredential,
  WrappedSdJwtVerifiableCredential,
  WrappedVerifiablePresentation,
  WrappedW3CVerifiableCredential,
} from '@sphereon/ssi-types'
import { DcqlPresentation, DcqlQuery } from 'dcql'
import { verifyRevocation } from '../helpers'
import { AuthorizationResponse } from './AuthorizationResponse'
import { Dcql } from './Dcql'
import { PresentationSubmission, RevocationVerification, VerifiedOpenID4VPSubmission } from '../types'
import { VerifyAuthorizationResponseOpts } from './types'

export const extractNonceFromWrappedVerifiablePresentation = (wrappedVp: WrappedVerifiablePresentation): string | undefined => {
  // SD-JWT uses kb-jwt for the nonce
  if (CredentialMapper.isWrappedSdJwtVerifiablePresentation(wrappedVp)) {
    // SD-JWT uses kb-jwt for the nonce
    // TODO: replace this once `kbJwt.payload` is available on the decoded sd-jwt (pr in ssi-sdk)
    // If it doesn't end with ~, it contains a kbJwt
    if (!wrappedVp.presentation.compactSdJwtVc.endsWith('~')) {
      return wrappedVp.presentation.kbJwt?.payload?.nonce
    }

    // No kb-jwt means no nonce (error will be handled later)
    return undefined
  }

  if (wrappedVp.format === 'jwt_vp') {
    return wrappedVp.decoded.nonce
  }

  // For LDP-VP a challenge is also fine
  if (wrappedVp.format === 'ldp_vp') {
    const w3cPresentation = wrappedVp.decoded as IVerifiablePresentation
    const proof = Array.isArray(w3cPresentation.proof) ? w3cPresentation.proof[0] : w3cPresentation.proof

    return proof.nonce ?? proof.challenge
  }

  return undefined
}

export const verifyPresentations = async (
  authorizationResponse: AuthorizationResponse,
  verifyOpts: VerifyAuthorizationResponseOpts,
): Promise<{ dcql: VerifiedOpenID4VPSubmission }> => {
  const dcqlQuery = DcqlQuery.parse(verifyOpts.dcqlQuery ?? (authorizationResponse?.authorizationRequest.payload.dcql_query as DcqlQuery))
  DcqlQuery.validate(dcqlQuery)
  const dcqlPresentation = extractDcqlPresentationFromDcqlVpToken(authorizationResponse.payload.vp_token as string, { hasher: verifyOpts.hasher })

  const wrappedPresentations = Object.values(dcqlPresentation)
  const verifiedPresentations = await Promise.all(
    wrappedPresentations.map((presentation) =>
      verifyOpts.verification.presentationVerificationCallback?.(presentation.original as W3CVerifiablePresentation),
    ),
  )

  const dcqlPresentationResult = await Dcql.assertValidDcqlPresentationResult(authorizationResponse.payload.vp_token as string, dcqlQuery, {
    hasher: verifyOpts.hasher,
  })

  if (verifiedPresentations.some((verified) => !verified)) {
    const message = verifiedPresentations
      .filter((verified) => !!verified)
      .map((verified) => verified.reason)
      .filter(Boolean)
      .join(', ')

    throw Error(`Failed to verify presentations. ${message}`)
  }

  const presentationsWithoutMdoc = wrappedPresentations.filter((p) => p.format !== 'mso_mdoc')
  const nonces = new Set(presentationsWithoutMdoc.map(extractNonceFromWrappedVerifiablePresentation))
  if (presentationsWithoutMdoc.length > 0 && nonces.size !== 1) {
    throw Error(`${nonces.size} nonce values found for ${presentationsWithoutMdoc.length}. Should be 1`)
  }

  // Nonce may be undefined in case there's only mdoc presentations (verified differently)
  const nonce = Array.from(nonces)[0] as string | undefined
  if (presentationsWithoutMdoc.length > 0 && typeof nonce !== 'string') {
    throw new Error('Expected all presentations to contain a nonce value')
  }

  const revocationVerification = verifyOpts.verification?.revocationOpts
    ? verifyOpts.verification.revocationOpts.revocationVerification
    : RevocationVerification.IF_PRESENT
  if (revocationVerification !== RevocationVerification.NEVER) {
    if (!verifyOpts.verification.revocationOpts?.revocationVerificationCallback) {
      throw Error(`Please provide a revocation callback as revocation checking of credentials and presentations is not disabled`)
    }
    for (const vp of wrappedPresentations) {
      await verifyRevocation(vp, verifyOpts.verification.revocationOpts.revocationVerificationCallback, revocationVerification)
    }
  }

  return { dcql: { nonce, presentation: dcqlPresentation, dcqlQuery, dcqlPresentationResult } }
}

export const extractDcqlPresentationFromDcqlVpToken = (
  vpToken: DcqlPresentation.Input | string,
  opts?: { hasher?: HasherSync },
): PresentationSubmission => {
  return Object.fromEntries(
    Object.entries(DcqlPresentation.parse(vpToken)).map(([credentialQueryId, vp]) => {
      let singleVp: W3CVerifiablePresentation | CompactSdJwtVc | string

      if (Array.isArray(vp)) {
        if (vp.length === 0) {
          throw new Error(`DCQL query '${credentialQueryId}' has empty array of presentations`)
        }
        if (vp.length > 1) {
          throw new Error(`DCQL query '${credentialQueryId}' has multiple presentations (${vp.length}), but only one is supported atm`)
        }
        singleVp = vp[0]
      } else {
        singleVp = vp
      }

      return [
        credentialQueryId,
        CredentialMapper.toWrappedVerifiablePresentation(singleVp as W3CVerifiablePresentation | CompactSdJwtVc | string, { hasher: opts?.hasher }),
      ]
    }),
  )
}

export const extractPresentationsFromDcqlVpToken = (
  vpToken: DcqlPresentation.Input | string,
  opts?: { hasher?: HasherSync },
): WrappedVerifiablePresentation[] => {
  return Object.values(extractDcqlPresentationFromDcqlVpToken(vpToken, opts))
}

// FIXME probably too naive
export const hasCryptographicHolderBinding = (
  format: 'mso_mdoc' | 'dc+sd-jwt' | 'jwt_vc_json' | 'ldp_vc',
  vc: WrappedMdocCredential | WrappedSdJwtVerifiableCredential | WrappedW3CVerifiableCredential,
): boolean => {
  switch (format) {
    case 'mso_mdoc':
      return true
    case 'dc+sd-jwt':
      const sdJwt = vc as WrappedSdJwtVerifiableCredential
      return Boolean(sdJwt.decoded?.cnf?.jwk || sdJwt.decoded?.cnf?.kid)
    case 'jwt_vc_json':
      const jwt = vc as WrappedW3CVerifiableCredential
      return Boolean(jwt.decoded?.proof?.verificationMethod)
    case 'ldp_vc':
      const ldp = vc as WrappedW3CVerifiableCredential
      return Boolean(ldp.decoded?.proof?.verificationMethod)
  }
}
