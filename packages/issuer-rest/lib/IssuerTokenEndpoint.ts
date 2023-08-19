import { GrantTypes, PRE_AUTHORIZED_CODE_REQUIRED_ERROR, TokenError, TokenErrorResponse } from '@sphereon/oid4vci-common'
import { assertValidAccessTokenRequest, createAccessTokenResponse, ITokenEndpointOpts, VcIssuer } from '@sphereon/oid4vci-issuer'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { NextFunction, Request, Response } from 'express'
import { v4 } from 'uuid'

/**
 *
 * @param tokenExpiresIn
 * @param accessTokenSignerCallback
 * @param accessTokenIssuer
 * @param cNonceExpiresIn
 * @param issuer
 * @param interval
 */
export const handleTokenRequest = <T extends object>({
  tokenExpiresIn,
  accessTokenSignerCallback,
  accessTokenIssuer,
  cNonceExpiresIn,
  issuer,
  interval,
}: Required<Pick<ITokenEndpointOpts, 'accessTokenIssuer' | 'cNonceExpiresIn' | 'interval' | 'accessTokenSignerCallback' | 'tokenExpiresIn'>> & {
  issuer: VcIssuer<T>
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

    try {
      const responseBody = await createAccessTokenResponse(request.body, {
        credentialOfferSessions: issuer.credentialOfferSessions,
        accessTokenIssuer,
        cNonces: issuer.cNonces,
        cNonce: v4(),
        accessTokenSignerCallback,
        cNonceExpiresIn,
        interval,
        tokenExpiresIn,
      })
      return response.status(200).json(responseBody)
    } catch (error) {
      return sendErrorResponse(
        response,
        400,
        {
          error: TokenErrorResponse.invalid_request,
        },
        error,
      )
    }
  }
}

export const verifyTokenRequest = <T extends object>({
  preAuthorizedCodeExpirationDuration,
  issuer,
}: Required<Pick<ITokenEndpointOpts, 'preAuthorizedCodeExpirationDuration'> & { issuer: VcIssuer<T> }>) => {
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
