import { AuthorizationRequestPayloadD28Schema, AuthorizationRequestPayloadV1Schema } from '../schemas'
import { AuthorizationRequestPayload, SupportedVersion } from '../types'

export const authorizationRequestVersionDiscovery = (authorizationRequest: AuthorizationRequestPayload): SupportedVersion[] => {
  // 1. Heuristic checks first (strongest signals from version-specific fields)
  const hasVerifierInfo = 'verifier_info' in authorizationRequest && authorizationRequest.verifier_info !== undefined
  const hasRequestUriMethod = 'request_uri_method' in authorizationRequest && authorizationRequest.request_uri_method !== undefined
  const hasExpectedOrigins = 'expected_origins' in authorizationRequest && authorizationRequest.expected_origins !== undefined
  const hasWalletNonce = 'wallet_nonce' in authorizationRequest && authorizationRequest.wallet_nonce !== undefined
  const hasVerifierAttestations = 'verifier_attestations' in authorizationRequest && authorizationRequest.verifier_attestations !== undefined

  // V1-only fields present -> definitely V1
  if (hasVerifierInfo || hasRequestUriMethod || hasExpectedOrigins || hasWalletNonce) {
    return [SupportedVersion.OID4VP_v1]
  }

  // D28-only field present (without any V1 fields) -> definitely D28
  if (hasVerifierAttestations) {
    return [SupportedVersion.SIOPv2_OID4VP_D28]
  }

  // 2. Fall back to schema validation for ambiguous payloads
  const versions: SupportedVersion[] = []

  if (AuthorizationRequestPayloadD28Schema(authorizationRequest)) {
    versions.push(SupportedVersion.SIOPv2_OID4VP_D28)
  }

  if (AuthorizationRequestPayloadV1Schema(authorizationRequest)) {
    versions.push(SupportedVersion.OID4VP_v1)
  }

  // 3. Default to V1 if still ambiguous
  if (versions.length === 0) {
    versions.push(SupportedVersion.OID4VP_v1)
  }
  return versions
}

export const checkSIOPSpecVersionSupported = async (
  payload: AuthorizationRequestPayload,
  supportedVersions: SupportedVersion[],
): Promise<SupportedVersion[]> => {
  const versions: SupportedVersion[] = authorizationRequestVersionDiscovery(payload)
  if (!supportedVersions || supportedVersions.length === 0) {
    return versions
  }
  return supportedVersions.filter((version) => versions.includes(version))
}
