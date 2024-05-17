import { getJson, OpenIDResponse, WellKnownEndpoints } from '@sphereon/oid4vci-common';
import Debug from 'debug';

const debug = Debug('sphereon:openid4vci:openid-utils');
/**
 * Allows to retrieve information from a well-known location
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
  const result: OpenIDResponse<T> = await getJson(`${host.endsWith('/') ? host.slice(0, -1) : host}${endpointType}`, {
    exceptionOnHttpErrorStatus: opts?.errorOnNotFound,
  });
  if (result.origResponse.status >= 400) {
    // We only get here when error on not found is false
    debug(`host ${host} with endpoint type ${endpointType} status: ${result.origResponse.status}, ${result.origResponse.statusText}`);
  }
  return result;
};
