import { DPoPVerifyJwtCallback, JWK, uuidv4, verifyDPoP } from '@sphereon/oid4vc-common'
import { GrantTypes, PRE_AUTHORIZED_CODE_REQUIRED_ERROR, TokenError, TokenErrorResponse } from '@sphereon/oid4vci-common'
import { assertValidAccessTokenRequest, createAccessTokenResponse, ITokenEndpointOpts, VcIssuer } from '@sphereon/oid4vci-issuer'
import { sendErrorResponse } from '@sphereon/ssi-express-support'
import { NextFunction, Request, Response } from 'express'

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
  tokenExpiresIn, // expiration in seconds
  accessTokenEndpoint,
  accessTokenSignerCallback,
  accessTokenIssuer,
  cNonceExpiresIn, // expiration in seconds
  issuer,
  interval,
  dpop,
}: Required<Pick<ITokenEndpointOpts, 'accessTokenIssuer' | 'cNonceExpiresIn' | 'interval' | 'accessTokenSignerCallback' | 'tokenExpiresIn'>> & {
  issuer: VcIssuer<T>
  dpop?: {
    requireDPoP?: boolean
    dPoPVerifyJwtCallback: DPoPVerifyJwtCallback
  }
  // The full URL of the access token endpoint
  accessTokenEndpoint?: string
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

    if (request.headers.authorization && request.headers.authorization.startsWith('DPoP ') && !request.headers.DPoP) {
      return sendErrorResponse(response, 400, {
        error: TokenErrorResponse.invalid_request,
        error_description: 'DPoP header is required',
      })
    }

    let dPoPJwk: JWK | undefined
    if (dpop?.requireDPoP && !request.headers.dpop) {
      return sendErrorResponse(response, 400, {
        error: TokenErrorResponse.invalid_request,
        error_description: 'DPoP is required for requesting access tokens.',
      })
    }

    if (request.headers.dpop) {
      if (!dpop) {
        console.error('Received unsupported DPoP header. The issuer is not configured to work with DPoP. Provide DPoP options for it to work.')

        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_request,
          error_description: 'Received unsupported DPoP header.',
        })
      }

      try {
        const fullUrl = accessTokenEndpoint ?? request.protocol + '://' + request.get('host') + request.originalUrl
        dPoPJwk = await verifyDPoP(
          { method: request.method, headers: request.headers, fullUrl },
          {
            jwtVerifyCallback: dpop.dPoPVerifyJwtCallback,
            expectAccessToken: false,
            maxIatAgeInSeconds: undefined,
          },
        )
      } catch (error) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_dpop_proof,
          error_description: error instanceof Error ? error.message : 'Unknown error',
        })
      }
    }

    try {
      const responseBody = await createAccessTokenResponse(request.body, {
        credentialOfferSessions: issuer.credentialOfferSessions,
        accessTokenIssuer,
        cNonces: issuer.cNonces,
        cNonce: uuidv4(),
        accessTokenSignerCallback,
        cNonceExpiresIn,
        interval,
        tokenExpiresIn,
        dPoPJwk,
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
