import { checkExp } from '@sphereon/oid4vc-common';
import * as v from 'valibot';

export const vJarmAuthResponseErrorParams = v.looseObject({
  error: v.string(),
  state: v.optional(v.string()),

  error_description: v.pipe(
    v.optional(v.string()),
    v.description('Text providing additional information, used to assist the client developer in understanding the error that occurred.'),
  ),

  error_uri: v.pipe(
    v.optional(v.pipe(v.string(), v.url())),
    v.description(
      'A URI identifying a human-readable web page with information about the error, used to provide the client developer with additional information about the error',
    ),
  ),
});

export const vJarmAuthResponseParams = v.looseObject({
  state: v.optional(v.string()),

  /**
   * The issuer URL of the authorization server that created the response
   */
  iss: v.string(),

  /**
   * The client_id of the client the response is intended for
   */
  exp: v.number(),

  /**
   * Expiration of the JWT
   */
  aud: v.string(),
});

export type JarmAuthResponseParams = v.InferInput<typeof vJarmAuthResponseParams>;

export const validateJarmAuthResponseParams = (input: {
  authRequestParams: { client_id: string; state?: string };
  authResponseParams: JarmAuthResponseParams;
}) => {
  const { authRequestParams, authResponseParams } = input;
  // 2. The client obtains the state parameter from the JWT and checks its binding to the user agent. If the check fails, the client MUST abort processing and refuse the response.
  if (authRequestParams.state !== authResponseParams.state) {
    throw new Error(`State missmatch in jarm-auth-response. Expected '${authRequestParams.state}' received '${authRequestParams.state}'.`);
  }

  // 4. The client obtains the aud element from the JWT and checks whether it matches the client id the client used to identify itself in the corresponding authorization request. If the check fails, the client MUST abort processing and refuse the response.
  if (authRequestParams.client_id !== authResponseParams.client_id) {
    throw new Error(`Invalid audience in jarm-auth-response. Expected '${authRequestParams.client_id}' received '${authResponseParams.aud}'.`);
  }

  // 5. The client checks the JWT's exp element to determine if the JWT is still valid. If the check fails, the client MUST abort processing and refuse the response.
  // 120 seconds clock skew
  if (checkExp({ exp: authResponseParams.exp })) {
    throw new Error(`The '${authRequestParams.state}' and the jarm-auth-response.`);
  }
};
