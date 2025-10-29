import {
  AuthorizationRequestPayloadD28Schema,
  AuthorizationRequestPayloadV1Schema
} from '../schemas'
import { AuthorizationRequestPayload, SupportedVersion } from '../types'

export const authorizationRequestVersionDiscovery = (authorizationRequest: AuthorizationRequestPayload): SupportedVersion[] => {
  const versions = []
  const authorizationRequestCopy: AuthorizationRequestPayload = JSON.parse(JSON.stringify(authorizationRequest))

  const d28Validation = AuthorizationRequestPayloadD28Schema(authorizationRequestCopy)
  if (d28Validation) {
    versions.push(SupportedVersion.SIOPv2_OID4VP_D28)
  }

  const v1Validation = AuthorizationRequestPayloadV1Schema(authorizationRequestCopy)
  if (v1Validation) {
    versions.push(SupportedVersion.OID4VP_v1)
  }

  if (versions.length === 0) {
    // For now just defaulting to v1 of OID4VP
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
