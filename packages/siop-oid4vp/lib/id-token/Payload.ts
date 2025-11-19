import { AuthorizationResponseOpts, mergeOAuth2AndOpenIdInRequestPayload } from '../authorization-response'
import { assertValidResponseOpts } from '../authorization-response/Opts'
import { authorizationRequestVersionDiscovery } from '../helpers/SIOPSpecVersion'
import { IDTokenPayload, ResponseIss, SIOPErrors, VerifiedAuthorizationRequest } from '../types'

export const createIDTokenPayload = async (
  verifiedAuthorizationRequest: VerifiedAuthorizationRequest,
  responseOpts: AuthorizationResponseOpts,
): Promise<IDTokenPayload> => {
  assertValidResponseOpts(responseOpts)
  const authorizationRequestPayload = verifiedAuthorizationRequest.authorizationRequest.mergedPayloads()
  const requestObject = verifiedAuthorizationRequest.requestObject
  if (!authorizationRequestPayload) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS)
  }
  const payload = await mergeOAuth2AndOpenIdInRequestPayload(authorizationRequestPayload, requestObject)

  const state = payload.state
  const nonce = payload.nonce
  const SEC_IN_MS = 1000

  const rpSupportedVersions = authorizationRequestVersionDiscovery(payload)

  if (responseOpts.version && rpSupportedVersions.length > 0 && !rpSupportedVersions.includes(responseOpts.version)) {
    throw Error(`RP does not support spec version ${responseOpts.version}, supported versions: ${rpSupportedVersions.toString()}`)
  }

  return {
    iss: responseOpts?.registration?.issuer ?? ResponseIss.SELF_ISSUED_V2,
    aud: responseOpts.audience || payload.client_id,
    iat: Math.round(Date.now() / SEC_IN_MS - 60 * SEC_IN_MS),
    exp: Math.round(Date.now() / SEC_IN_MS + (responseOpts.expiresIn || 600)),
    ...(payload.auth_time && { auth_time: payload.auth_time }),
    nonce,
    state,
  }
}
