import { DcqlPresentation } from 'dcql'
import { AuthorizationRequest } from '../authorization-request'
import { IDToken } from '../id-token'
import { RequestObject } from '../request-object'
import { assertValidResponseOpts } from './Opts'
import {
  AuthorizationRequestPayload,
  AuthorizationResponsePayload,
  DcqlPresentationEntry,
  DcqlVpToken,
  DcqlVpTokenInput,
  IDTokenPayload,
  NonEmptyArray,
  SIOPErrors
} from '../types'
import { AuthorizationResponseOpts } from './types'


/**
 * Checks if an object is array-like (has only numeric string keys: "0", "1", "2", etc.)
 * This handles objects that were serialized arrays: { "0": val1, "1": val2 }
 */
const isArrayLikeObject = (value: unknown): value is Record<string, DcqlPresentationEntry> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return false
  }
  const keys = Object.keys(value)
  return keys.length > 0 && keys.every(key => /^\d+$/.test(key))
}

/**
 * Normalizes a credential query value to an array.
 * Handles three input formats:
 * 1. Single value: "credential" -> ["credential"]
 * 2. Array: ["cred1", "cred2"] -> ["cred1", "cred2"]
 * 3. Array-like object: {"0": "cred1", "1": "cred2"} -> ["cred1", "cred2"]
 */
const normalizeToArray = (
  credentialQueryId: string,
  value: DcqlPresentationEntry | DcqlPresentationEntry[] | Record<string, DcqlPresentationEntry>
): NonEmptyArray<DcqlPresentationEntry> => {
  let presentationsArray: DcqlPresentationEntry[]

  if (Array.isArray(value)) {
    presentationsArray = value
  } else if (isArrayLikeObject(value)) {
    const sortedKeys = Object.keys(value).sort((a, b) => Number(a) - Number(b))
    presentationsArray = sortedKeys.map(key => value[key])
  } else {
    presentationsArray = [value]
  }

  if (presentationsArray.length === 0) {
    throw new Error(
      `DCQL presentations for credential query '${credentialQueryId}' cannot be empty`
    )
  }

  return presentationsArray as NonEmptyArray<DcqlPresentationEntry>
}

/**
 * Converts a DCQL presentation input (which may have mixed formats) to the canonical
 * format where all credential queries map to non-empty arrays of presentations.
 *
 * This ensures consistent handling of:
 * - Single presentations: { "PID": "eyJ..." } -> { "PID": ["eyJ..."] }
 * - Array presentations: { "PID": ["eyJ..."] } -> { "PID": ["eyJ..."] }
 * - Array-like objects: { "PID": {"0": "eyJ..."} } -> { "PID": ["eyJ..."] }
 */
const toCanonicalDcqlPresentation = (input: DcqlVpTokenInput): DcqlVpToken => {
  return Object.fromEntries(
    Object.entries(input).map(([credentialQueryId, value]) => {
      const presentationsArray = normalizeToArray(credentialQueryId, value)
      return [credentialQueryId, presentationsArray]
    })
  ) as DcqlVpToken
}


export const createResponsePayload = async (
  authorizationRequest: AuthorizationRequest,
  responseOpts: AuthorizationResponseOpts,
  idTokenPayload?: IDTokenPayload
): Promise<AuthorizationResponsePayload | undefined> => {
  assertValidResponseOpts(responseOpts)
  if (!authorizationRequest) {
    throw new Error(SIOPErrors.NO_REQUEST)
  }

  // If state was in request, it must be in response
  const state: string | undefined = authorizationRequest.getMergedProperty('state')

  const responsePayload: AuthorizationResponsePayload = {
    ...(responseOpts.accessToken && {
      access_token: responseOpts.accessToken,
      expires_in: responseOpts.expiresIn || 3600
    }),
    ...(responseOpts.tokenType && { token_type: responseOpts.tokenType }),
    ...(responseOpts.refreshToken && { refresh_token: responseOpts.refreshToken }),
    ...(responseOpts.isFirstParty && { is_first_party: responseOpts.isFirstParty }),
    state
  }

  if (responseOpts.dcqlResponse?.dcqlPresentation) {
    const canonicalPresentation = toCanonicalDcqlPresentation(
      responseOpts.dcqlResponse.dcqlPresentation
    )
    responsePayload.vp_token = DcqlPresentation.encode(canonicalPresentation)
  }

  if (idTokenPayload) {
    const idToken = await IDToken.fromIDTokenPayload(idTokenPayload, responseOpts)
    responsePayload.id_token = await idToken.jwt(responseOpts.jwtIssuer)
  }

  return responsePayload
}

/**
 * Properties can be in oAUth2 and OpenID (JWT) style. If they are in both the OpenID prop takes precedence as they are signed.
 * @param payload
 * @param requestObject
 */
export const mergeOAuth2AndOpenIdInRequestPayload = async (
  payload: AuthorizationRequestPayload,
  requestObject?: RequestObject
): Promise<AuthorizationRequestPayload> => {
  const payloadCopy = JSON.parse(JSON.stringify(payload))

  const requestObj = requestObject ? requestObject : await RequestObject.fromAuthorizationRequestPayload(payload)
  if (!requestObj) {
    return payloadCopy
  }
  const requestObjectPayload = requestObj.getPayload()
  return { ...payloadCopy, ...requestObjectPayload }
}
