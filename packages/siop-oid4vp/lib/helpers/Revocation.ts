import { CredentialMapper, W3CVerifiableCredential, WrappedVerifiableCredential, WrappedVerifiablePresentation } from '@sphereon/ssi-types'

import { MdocVerifiablePresentation } from '../authorization-response/OpenID4VP'
import { RevocationStatus, RevocationVerification, RevocationVerificationCallback, VerifiableCredentialTypeFormat } from '../types'

export const verifyRevocation = async (
  vpToken: WrappedVerifiablePresentation | MdocVerifiablePresentation,
  revocationVerificationCallback: RevocationVerificationCallback,
  revocationVerification: RevocationVerification,
): Promise<void> => {
  if (!vpToken) {
    throw new Error(`VP token not provided`)
  }
  if (!revocationVerificationCallback) {
    throw new Error(`Revocation callback not provided`)
  }

  if (vpToken instanceof MdocVerifiablePresentation) {
    return
  }

  const vcs = CredentialMapper.isWrappedSdJwtVerifiablePresentation(vpToken) ? [vpToken.vcs[0]] : vpToken.presentation.verifiableCredential
  for (const vc of vcs) {
    if (
      revocationVerification === RevocationVerification.ALWAYS ||
      (revocationVerification === RevocationVerification.IF_PRESENT && credentialHasStatus(vc))
    ) {
      const result = await revocationVerificationCallback(
        vc.original as W3CVerifiableCredential,
        originalTypeToVerifiableCredentialTypeFormat(vc.format),
      )
      if (result.status === RevocationStatus.INVALID) {
        throw new Error(`Revocation invalid for vc. Error: ${result.error}`)
      }
    }
  }
}

function originalTypeToVerifiableCredentialTypeFormat(original: WrappedVerifiableCredential['format']): VerifiableCredentialTypeFormat {
  const mapping: { [T in WrappedVerifiableCredential['format']]: VerifiableCredentialTypeFormat } = {
    'vc+sd-jwt': VerifiableCredentialTypeFormat.SD_JWT_VC,
    jwt: VerifiableCredentialTypeFormat.JWT_VC,
    jwt_vc: VerifiableCredentialTypeFormat.JWT_VC,
    ldp: VerifiableCredentialTypeFormat.LDP_VC,
    ldp_vc: VerifiableCredentialTypeFormat.LDP_VC,
  }

  return mapping[original]
}

/**
 * Checks whether a wrapped verifiable credential has a status in the credential.
 * For w3c credentials it will check the presence of `credentialStatus` property
 * For SD-JWT it will check the presence of `status` property
 */
function credentialHasStatus(wrappedVerifiableCredential: WrappedVerifiableCredential) {
  if (CredentialMapper.isWrappedSdJwtVerifiableCredential(wrappedVerifiableCredential)) {
    return wrappedVerifiableCredential.decoded.status !== undefined
  } else {
    return wrappedVerifiableCredential.credential.credentialStatus !== undefined
  }
}
