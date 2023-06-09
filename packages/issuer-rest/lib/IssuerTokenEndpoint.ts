import {
  AccessTokenResponse,
  GrantTypes,
  PRE_AUTH_CODE_LITERAL,
  PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
  TokenError,
  TokenErrorResponse,
} from '@sphereon/oid4vci-common'
import { assertValidAccessTokenRequest, generateAccessToken, ITokenEndpointOpts, VcIssuer } from '@sphereon/oid4vci-issuer'
import { NextFunction, Request, Response } from 'express'
import { v4 } from 'uuid'

import { sendErrorResponse } from './expressUtils'

/**
 *
 * @param tokenExpiresIn
 * @param accessTokenSignerCallback
 * @param accessTokenIssuer
 * @param cNonceExpiresIn
 * @param issuer
 * @param interval
 */
export const handleTokenRequest = ({
  tokenExpiresIn,
  accessTokenSignerCallback,
  accessTokenIssuer,
  cNonceExpiresIn,
  issuer,
  interval,
}: Required<Pick<ITokenEndpointOpts, 'accessTokenIssuer' | 'cNonceExpiresIn' | 'interval' | 'accessTokenSignerCallback' | 'tokenExpiresIn'>> & {
  issuer: VcIssuer
}) => {
  return async (request: Request, response: Response) => {
    response.set({
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
    })

    if (request.body.grant_type !== GrantTypes.PRE_AUTHORIZED_CODE) {
      // Yes this is redundant, only here to remind us that we need to implement the auth flow as well
      return sendErrorResponse(response, 400, {
        error: TokenErrorResponse.invalid_request,
        error_description: PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
      })
    }

    // Pre-auth flow
    const preAuthorizedCode = request.body[PRE_AUTH_CODE_LITERAL] as string

    const cNonce = v4()
    await issuer.cNonces.set(cNonce, { cNonce, createdAt: +new Date(), preAuthorizedCode })

    const access_token = await generateAccessToken({
      tokenExpiresIn,
      accessTokenSignerCallback,
      preAuthorizedCode,
      accessTokenIssuer,
    })
    const responseBody: AccessTokenResponse = {
      access_token,
      token_type: 'bearer',
      expires_in: tokenExpiresIn,
      c_nonce: cNonce,
      c_nonce_expires_in: cNonceExpiresIn,
      authorization_pending: false,
      interval,
    }
    return response.status(200).json(responseBody)
  }
}

export const verifyTokenRequest = ({
  preAuthorizedCodeExpirationDuration,
  issuer,
}: Required<Pick<ITokenEndpointOpts, 'preAuthorizedCodeExpirationDuration'> & { issuer: VcIssuer }>) => {
  return async (request: Request, response: Response, next: NextFunction) => {
    try {
      await assertValidAccessTokenRequest(request.body, {
        expirationDuration: preAuthorizedCodeExpirationDuration,
        credentialOfferSessions: issuer.credentialOfferSessions,
      })
    } catch (error) {
      if (error instanceof TokenError) {
        return sendErrorResponse(response, error.statusCode, {
          error: error.responseError,
          error_description: error.getDescription(),
        })
      } else {
        return sendErrorResponse(response, 400, { error: TokenErrorResponse.invalid_request, error_description: (error as Error).message }, error)
      }
    }

    return next()
  }
}
