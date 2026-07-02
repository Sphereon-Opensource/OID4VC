import { getJson, OpenIDResponse, WellKnownEndpoints } from '@sphereon/oid4vci-common'
import { Loggers } from '@sphereon/ssi-types'

const logger = Loggers.DEFAULT.get('sphereon:openid4vci:openid-utils')

/**
 * Determines the well-known location(s) to try for a host and endpoint type, in order of preference.
 *
 * OID4VCI 1.0 final and RFC 8414 require the well-known path to be inserted between the host and the path component
 * (https://host/.well-known/openid-credential-issuer/tenant), whereas earlier OID4VCI drafts appended it to the full
 * URL (https://host/tenant/.well-known/openid-credential-issuer). For the credential issuer and OAuth AS metadata we
 * default to the current spec behavior with the legacy location as fallback. For openid-configuration the appended
 * form is the primary location per OIDC Discovery, with the RFC 8414 form as fallback.
 *
 * @param host The host, including an optional path component
 * @param endpointType The endpoint type, currently supports OID4VCI, OIDC and OAuth2 endpoint types
 */
export const determineWellknownLocations = (host: string, endpointType: WellKnownEndpoints): string[] => {
  const base = host.endsWith('/') ? host.slice(0, -1) : host
  const legacyLocation = `${base}${endpointType}`
  try {
    const url = new URL(base)
    let pathname = url.pathname
    while (pathname.endsWith('/')) {
      pathname = pathname.slice(0, -1)
    }
    if (pathname.length > 0) {
      const rfc8414Location = `${url.origin}${endpointType}${pathname}`
      return endpointType === WellKnownEndpoints.OPENID_CONFIGURATION ? [legacyLocation, rfc8414Location] : [rfc8414Location, legacyLocation]
    }
  } catch (error) {
    logger.debug(`host ${host} could not be parsed as URL, using legacy well-known location only`)
  }
  return [legacyLocation]
}

/**
 * Allows to retrieve information from a well-known location
 *
 * Tries all applicable locations for the endpoint type (see determineWellknownLocations) and returns the first
 * successful response containing a JSON object body.
 *
 * @param host The host
 * @param endpointType The endpoint type, currently supports OID4VCI, OIDC and OAuth2 endpoint types
 * @param opts Options, like for instance whether an error should be thrown in case the endpoint doesn't exist
 */
export const retrieveWellknown = async <T>(
  host: string,
  endpointType: WellKnownEndpoints,
  opts?: { errorOnNotFound?: boolean },
): Promise<OpenIDResponse<T>> => {
  const locations = determineWellknownLocations(host, endpointType)
  let successResult: OpenIDResponse<T> | undefined
  let errorResult: OpenIDResponse<T> | undefined
  let lastError: unknown
  for (const location of locations) {
    try {
      const response: OpenIDResponse<T> = await getJson<T>(location, { exceptionOnHttpErrorStatus: false })
      if (response.origResponse.status < 400) {
        if (response.successBody !== undefined && typeof response.successBody === 'object' && response.successBody !== null) {
          return response
        }
        // Success status, but no JSON object body. Remember it, but prefer a location that returns a proper JSON object
        successResult = successResult ?? response
      } else {
        logger.debug(
          `host ${host} with endpoint type ${endpointType} at ${location} status: ${response.origResponse.status}, ${response.origResponse.statusText}`,
        )
        errorResult = errorResult ?? response
      }
    } catch (error) {
      logger.debug(`host ${host} with endpoint type ${endpointType} at ${location} error: ${error instanceof Error ? error.message : error}`)
      lastError = error
    }
  }
  if (successResult) {
    return successResult
  }
  if (errorResult) {
    if (opts?.errorOnNotFound) {
      // Same semantics as getJson with exceptionOnHttpErrorStatus enabled
      const error = JSON.stringify(errorResult.errorBody ?? {})
      throw new Error(error === '{}' ? '{"error": "not found"}' : error)
    }
    return errorResult
  }
  throw lastError instanceof Error ? lastError : new Error(`Could not retrieve well-known ${endpointType} for host ${host}`)
}
