import {
  AccessTokenResponse,
  Alg,
  CredentialOfferSession,
  EXPIRED_PRE_AUTHORIZED_CODE,
  getNumberOrUndefined,
  GrantType,
  INVALID_PRE_AUTHORIZED_CODE,
  Jwt,
  JWTSignerCallback,
  PIN_NOT_MATCH_ERROR,
  PIN_NOT_MATCHING_ERROR,
  PIN_VALIDATION_ERROR,
  PRE_AUTH_CODE_LITERAL,
  PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
  TokenErrorResponse,
  UNSUPPORTED_GRANT_TYPE_ERROR,
  USER_PIN_NOT_REQUIRED_ERROR,
  USER_PIN_REQUIRED_ERROR,
} from '@sphereon/oid4vci-common'
import { isPreAuthorizedCodeExpired, VcIssuer } from '@sphereon/oid4vci-issuer'
import { NextFunction, Request, Response } from 'express'
import { v4 } from 'uuid'

import { sendErrorResponse } from './expressUtils'

export interface ITokenEndpointOpts {
  tokenEndpointDisabled?: boolean // Disable if used in an existing OAuth2/OIDC environment and have the AS handle tokens
  tokenPath?: string // token path can either be defined here, or will be deduced from issuer metadata
  interval?: number
  cNonceExpiresIn?: number
  tokenExpiresIn?: number
  preAuthorizedCodeExpirationDuration?: number
  accessTokenSignerCallback?: JWTSignerCallback
  accessTokenIssuer?: string
}

export const generateAccessToken = async (
  opts: Required<Pick<ITokenEndpointOpts, 'accessTokenSignerCallback' | 'tokenExpiresIn' | 'accessTokenIssuer'>> & {
    preAuthorizedCode?: string
    alg?: Alg
  }
): Promise<string> => {
  const { accessTokenIssuer, alg, accessTokenSignerCallback, tokenExpiresIn, preAuthorizedCode } = opts
  const iat = new Date().getTime()
  const jwt: Jwt = {
    header: { typ: 'JWT', alg: alg ?? Alg.ES256K },
    payload: {
      iat,
      exp: tokenExpiresIn,
      iss: accessTokenIssuer,
      ...(preAuthorizedCode && { preAuthorizedCode }),
    },
  }
  return await accessTokenSignerCallback(jwt)
}

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

    if (request.body.grant_type !== GrantType.PRE_AUTHORIZED_CODE) {
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

export const isValidGrant = (assertedState: CredentialOfferSession, grantType: string): boolean => {
  if (assertedState.credentialOffer?.credential_offer?.grants) {
    // TODO implement authorization_code
    return (
      Object.keys(assertedState.credentialOffer?.credential_offer?.grants).includes(GrantType.PRE_AUTHORIZED_CODE) &&
      grantType === GrantType.PRE_AUTHORIZED_CODE
    )
  }
  return false
}

export const verifyTokenRequest = ({
  preAuthorizedCodeExpirationDuration,
  issuer,
}: Required<Pick<ITokenEndpointOpts, 'preAuthorizedCodeExpirationDuration'> & { issuer: VcIssuer }>) => {
  return async (request: Request, response: Response, next: NextFunction) => {
    // fixme: This should be moved to a separate function without request/responses, which then throws errors. In turn this function would call that function and return an error response.

    // Only pre-auth supported for now
    if (request.body.grant_type !== GrantType.PRE_AUTHORIZED_CODE) {
      return sendErrorResponse(response, 400, {
        error: TokenErrorResponse.invalid_grant,
        error_description: UNSUPPORTED_GRANT_TYPE_ERROR,
      })
    }

    // Pre-auth flow
    if (!request.body[PRE_AUTH_CODE_LITERAL]) {
      return sendErrorResponse(response, 400, {
        error: TokenErrorResponse.invalid_request,
        error_description: PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
      })
    }

    try {
      const credentialOfferSession = await issuer.credentialOfferSessions.getAsserted(request.body[PRE_AUTH_CODE_LITERAL])
      if (!isValidGrant(credentialOfferSession, request.body.grant_type)) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_grant,
          error_description: UNSUPPORTED_GRANT_TYPE_ERROR,
        })
      }
      /*
      invalid_request:
      the Authorization Server expects a PIN in the pre-authorized flow but the client does not provide a PIN
       */
      if (
        credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantType.PRE_AUTHORIZED_CODE]?.user_pin_required &&
        !request.body.user_pin
      ) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_request,
          error_description: USER_PIN_REQUIRED_ERROR,
        })
      }
      /*
      invalid_request:
      the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN
       */
      if (
        !credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantType.PRE_AUTHORIZED_CODE]?.user_pin_required &&
        request.body.user_pin
      ) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_request,
          error_description: USER_PIN_NOT_REQUIRED_ERROR,
        })
      }
      /*
      invalid_grant:
      the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN
      the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
       */
      if (request.body.user_pin && !/[0-9{,8}]/.test(request.body.user_pin)) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_grant,
          error_message: PIN_VALIDATION_ERROR,
        })
      }
      if (credentialOfferSession.userPin != getNumberOrUndefined(request.body.user_pin)) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_grant,
          error_message: PIN_NOT_MATCHING_ERROR,
        })
      }
      if (getNumberOrUndefined(request.body.user_pin) !== credentialOfferSession.userPin) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_grant,
          error_message: PIN_NOT_MATCH_ERROR,
        })
      } else if (isPreAuthorizedCodeExpired(credentialOfferSession, preAuthorizedCodeExpirationDuration)) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_grant,
          error_message: EXPIRED_PRE_AUTHORIZED_CODE,
        })
      } else if (
        request.body[PRE_AUTH_CODE_LITERAL] !==
        credentialOfferSession.credentialOffer?.credential_offer?.grants?.[GrantType.PRE_AUTHORIZED_CODE]?.[PRE_AUTH_CODE_LITERAL]
      ) {
        return sendErrorResponse(response, 400, {
          error: TokenErrorResponse.invalid_grant,
          error_message: INVALID_PRE_AUTHORIZED_CODE,
        })
      }
    } catch (error: any) {
      return sendErrorResponse(
        response,
        400,
        {
          error: TokenErrorResponse.invalid_request,
          error_message: 'message' in error ? error.message : 'unknown error occured',
        },
        error
      )
    }

    return next()
  }
}
