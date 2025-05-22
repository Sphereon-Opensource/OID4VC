import { decodeProtectedHeader, isJwe, isJws } from '@sphereon/oid4vc-common'
import * as v from 'valibot'

import type { AuthRequestParams, JarmDirectPostJwtAuthResponseValidationContext } from './c-jarm-auth-response'
import { vJarmAuthResponseErrorParams } from './v-jarm-auth-response-params'
import {
  jarmAuthResponseDirectPostValidateParams,
  JarmDirectPostJwtResponseParams,
  vJarmDirectPostJwtParams,
} from './v-jarm-direct-post-jwt-auth-response-params'

export interface JarmDirectPostJwtAuthResponseValidation {
  /**
   * The JARM response parameter conveyed either as url query param, fragment param, or application/x-www-form-urlencoded in the body of a post request
   */
  response: string
}

const parseJarmAuthResponseParams = <Schema extends v.BaseSchema<unknown, unknown, v.BaseIssue<unknown>>>(
  schema: Schema,
  responseParams: unknown,
) => {
  if (v.is(vJarmAuthResponseErrorParams, responseParams)) {
    const errorResponseJson = JSON.stringify(responseParams, undefined, 2)
    throw new Error(`Received error response from authorization server. '${errorResponseJson}'`)
  }

  return v.parse(schema, responseParams)
}

const decryptJarmAuthResponse = async (input: { response: string }, ctx: JarmDirectPostJwtAuthResponseValidationContext) => {
  const { response } = input

  const responseProtectedHeader = decodeProtectedHeader(response)
  if (!responseProtectedHeader.kid) {
    throw new Error(`Jarm JWE is missing the protected header field 'kid'.`)
  }

  const { plaintext } = await ctx.jwe.decryptCompact({
    jwe: response,
    jwk: { kid: responseProtectedHeader.kid },
  })

  return plaintext
}

/**
 * Validate a JARM direct_post.jwt compliant authentication response
 * * The decryption key should be resolvable using the the protected header's 'kid' field
 * * The signature verification jwk should be resolvable using the jws protected header's 'kid' field and the payload's 'iss' field.
 */
export const jarmAuthResponseDirectPostJwtValidate = async (
  input: JarmDirectPostJwtAuthResponseValidation,
  ctx: JarmDirectPostJwtAuthResponseValidationContext,
) => {
  const { response } = input

  const responseIsEncrypted = isJwe(response)
  const decryptedResponse = responseIsEncrypted ? await decryptJarmAuthResponse(input, ctx) : response

  const responseIsSigned = isJws(decryptedResponse)
  if (!responseIsEncrypted && !responseIsSigned) {
    throw new Error('Jarm Auth Response must be either encrypted, signed, or signed and encrypted.')
  }

  let authResponseParams: JarmDirectPostJwtResponseParams
  let authRequestParams: AuthRequestParams

  if (responseIsSigned) {
    throw new Error('Signed JARM responses are not supported.')
    //const jwsProtectedHeader = decodeProtectedHeader(decryptedResponse);
    //const jwsPayload = decodeJwt(decryptedResponse);

    //const schema = v.required(vJarmDirectPostJwtParams, ['iss', 'aud', 'exp']);
    //const responseParams = parseJarmAuthResponseParams(schema, jwsPayload);
    //({ authRequestParams } = await ctx.openid4vp.authRequest.getParams(responseParams));

    //if (!jwsProtectedHeader.kid) {
    //throw new Error(`Jarm JWS is missing the protected header field 'kid'.`);
    //}

    //await ctx.jose.jws.verifyJwt({
    //jws: decryptedResponse,
    //jwk: { kid: jwsProtectedHeader.kid, kty: 'auto' },
    //});
    //authResponseParams = responseParams;
  } else {
    const jsonResponse: unknown = JSON.parse(decryptedResponse)
    authResponseParams = parseJarmAuthResponseParams(vJarmDirectPostJwtParams, jsonResponse)
    ;({ authRequestParams } = await ctx.openid4vp.authRequest.getParams(authResponseParams))
  }

  jarmAuthResponseDirectPostValidateParams({
    authRequestParams,
    authResponseParams,
  })

  let type: 'signed encrypted' | 'encrypted' | 'signed'
  if (responseIsSigned && responseIsEncrypted) type = 'signed encrypted'
  else if (responseIsEncrypted) type = 'encrypted'
  else type = 'signed'

  return {
    authRequestParams,
    authResponseParams,
    type,
  }
}
