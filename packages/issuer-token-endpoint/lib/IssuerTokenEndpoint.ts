import {
  ACCESS_TOKEN_ISSUER_REQUIRED_ERROR,
  AccessTokenResponse,
  Alg,
  CNonceState,
  CredentialOfferState,
  EXPIRED_PRE_AUTHORIZED_CODE,
  getNumberOrUndefined,
  GrantType,
  INVALID_PRE_AUTHORIZED_CODE,
  IStateManager,
  Jwt,
  JWT_SIGNER_CALLBACK_REQUIRED_ERROR,
  JWTSignerCallback,
  NONCE_STATE_MANAGER_REQUIRED_ERROR,
  PIN_NOT_MATCH_ERROR,
  PIN_NOT_MATCHING_ERROR,
  PIN_VALIDATION_ERROR,
  PRE_AUTH_CODE_LITERAL,
  PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
  STATE_MANAGER_REQUIRED_ERROR,
  TokenErrorResponse,
  Typ,
  UNSUPPORTED_GRANT_TYPE_ERROR,
  USER_PIN_NOT_REQUIRED_ERROR,
  USER_PIN_REQUIRED_ERROR,
} from '@sphereon/oid4vci-common'
import express, { NextFunction, Request, Response, Router } from 'express'
import { v4 } from 'uuid'

const router = express.Router()

interface ITokenEndpointOpts {
  tokenPath?: string
  interval?: number
  cNonceExpiresIn?: number
  tokenExpiresIn?: number
  preAuthorizedCodeExpirationDuration?: number
  stateManager?: IStateManager<CredentialOfferState>
  nonceStateManager?: IStateManager<CNonceState>
  accessTokenSignerCallback?: JWTSignerCallback
  accessTokenIssuer?: string
}

export const tokenRequestEndpoint = (opts?: ITokenEndpointOpts): Router => {
  const tokenPath = opts?.tokenPath ?? process.env.TOKEN_PATH ?? '/token'
  const accessTokenIssuer = opts?.accessTokenIssuer ?? process.env.ACCESS_TOKEN_ISSUER
  const preAuthorizedCodeExpirationDuration =
    opts?.preAuthorizedCodeExpirationDuration ?? getNumberOrUndefined(process.env.PRE_AUTHORIZED_CODE_EXPIRATION_DURATION) ?? 300000
  const interval = opts?.interval ?? getNumberOrUndefined(process.env.INTERVAL) ?? 300000
  const cNonceExpiresIn = opts?.cNonceExpiresIn ?? getNumberOrUndefined(process.env.C_NONCE_EXPIRES_IN) ?? 300000
  const tokenExpiresIn = opts?.tokenExpiresIn ?? getNumberOrUndefined(process.env.TOKEN_EXPIRES_IN) ?? 300000
  if (!opts?.accessTokenSignerCallback) {
    throw new Error(JWT_SIGNER_CALLBACK_REQUIRED_ERROR)
  }
  if (!opts?.stateManager) {
    throw new Error(STATE_MANAGER_REQUIRED_ERROR)
  }
  if (!opts?.nonceStateManager) {
    throw new Error(NONCE_STATE_MANAGER_REQUIRED_ERROR)
  }
  if (!accessTokenIssuer) {
    throw new Error(ACCESS_TOKEN_ISSUER_REQUIRED_ERROR)
  }
  router.post(
    tokenPath,
    handleHTTPStatus400({ stateManager: opts.stateManager, preAuthorizedCodeExpirationDuration }),
    handleTokenRequest({
      accessTokenSignerCallback: opts.accessTokenSignerCallback,
      nonceStateManager: opts.nonceStateManager,
      cNonceExpiresIn,
      interval,
      tokenExpiresIn,
      accessTokenIssuer,
    })
  )
  return router
}

const generateAccessToken = async (
  opts: Required<Pick<ITokenEndpointOpts, 'accessTokenSignerCallback' | 'tokenExpiresIn' | 'accessTokenIssuer'> & { state: string }>
): Promise<string> => {
  const issuanceTime = new Date()
  const jwt: Jwt = {
    header: { typ: Typ.JWT, alg: Alg.ES256 },
    payload: { iat: issuanceTime.getTime(), exp: opts.tokenExpiresIn, iss: opts.accessTokenIssuer, state: opts.state },
  }
  return await opts.accessTokenSignerCallback(jwt)
}

const handleTokenRequest = (
  opts: Required<
    Pick<
      ITokenEndpointOpts,
      'accessTokenIssuer' | 'cNonceExpiresIn' | 'interval' | 'accessTokenSignerCallback' | 'nonceStateManager' | 'tokenExpiresIn'
    >
  >
) => {
  return async (request: Request, response: Response) => {
    response.set({
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
    })

    const cNonce = v4()
    await opts.nonceStateManager?.setState(cNonce, { cNonce: v4(), createdOn: +new Date() })

    const access_token = await generateAccessToken({
      tokenExpiresIn: opts.tokenExpiresIn,
      accessTokenSignerCallback: opts.accessTokenSignerCallback,
      state: request.body.state,
      accessTokenIssuer: opts.accessTokenIssuer,
    })
    const responseBody: AccessTokenResponse = {
      access_token,
      token_type: 'bearer',
      expires_in: opts.tokenExpiresIn,
      c_nonce: cNonce,
      c_nonce_expires_in: opts.cNonceExpiresIn,
      authorization_pending: false,
      interval: opts.interval,
    }
    return response.status(200).json(responseBody)
  }
}

const isValidGrant = (assertedState: CredentialOfferState, grantType: string): boolean => {
  if (assertedState.credentialOffer?.credential_offer?.grants) {
    // TODO implement authorization_code
    return (
      Object.keys(assertedState.credentialOffer?.credential_offer?.grants).includes(GrantType.PRE_AUTHORIZED_CODE) &&
      grantType === GrantType.PRE_AUTHORIZED_CODE
    )
  }
  return false
}

export const handleHTTPStatus400 = (opts: Required<Pick<ITokenEndpointOpts, 'preAuthorizedCodeExpirationDuration' | 'stateManager'>>) => {
  return async (request: Request, response: Response, next: NextFunction) => {
    const assertedState = (await opts.stateManager.getAssertedState(request.body.state)) as CredentialOfferState
    if (!isValidGrant(assertedState, request.body.grant_type)) {
      return response.status(400).json({ error: TokenErrorResponse.invalid_grant, error_description: UNSUPPORTED_GRANT_TYPE_ERROR })
    }
    if (request.body.grant_type == GrantType.PRE_AUTHORIZED_CODE) {
      if (!request.body[PRE_AUTH_CODE_LITERAL]) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_request, error_description: PRE_AUTHORIZED_CODE_REQUIRED_ERROR })
      }
      /*
      invalid_request:
      the Authorization Server expects a PIN in the pre-authorized flow but the client does not provide a PIN
       */
      if (assertedState.credentialOffer.credential_offer?.grants?.[GrantType.PRE_AUTHORIZED_CODE]?.user_pin_required && !request.body.user_pin) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_request, error_description: USER_PIN_REQUIRED_ERROR })
      }
      /*
      invalid_request:
      the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN
       */
      if (!assertedState.credentialOffer.credential_offer?.grants?.[GrantType.PRE_AUTHORIZED_CODE]?.user_pin_required && request.body.user_pin) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_request, error_description: USER_PIN_NOT_REQUIRED_ERROR })
      }
      /*
      invalid_grant:
      the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN
      the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
       */
      if (request.body.user_pin && !/[0-9{,8}]/.test(request.body.user_pin)) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_grant, error_message: PIN_VALIDATION_ERROR })
      }
      if (assertedState.userPin != getNumberOrUndefined(request.body.user_pin)) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_grant, error_message: PIN_NOT_MATCHING_ERROR })
      }
      if (getNumberOrUndefined(request.body.user_pin) !== assertedState.userPin) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_grant, error_message: PIN_NOT_MATCH_ERROR })
      } else if (
        request.body[PRE_AUTH_CODE_LITERAL] !==
        assertedState.credentialOffer?.credential_offer?.grants?.[GrantType.PRE_AUTHORIZED_CODE]?.[PRE_AUTH_CODE_LITERAL]
      ) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_grant, error_message: INVALID_PRE_AUTHORIZED_CODE })
      } else if (isPreAuthorizedCodeExpired(assertedState, opts.preAuthorizedCodeExpirationDuration)) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_grant, error_message: EXPIRED_PRE_AUTHORIZED_CODE })
      }
    }
    return next()
  }
}

const isPreAuthorizedCodeExpired = (state: CredentialOfferState, expirationDuration: number) => {
  const now = +new Date()
  const expirationTime = state.createdOn + expirationDuration
  return now >= expirationTime
}
