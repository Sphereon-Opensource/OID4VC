import {
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
} from '@sphereon/openid4vci-common'
import express, { NextFunction, Request, Response, Router } from 'express'
import { v4 } from 'uuid'

const router = express.Router()

interface ITokenEndpointOpts {
  tokenPath?: string
  interval?: number
  cNonceExpiresIn?: number
  tokenExpiresIn?: number
  stateManager?: IStateManager<CredentialOfferState>
  nonceStateManager?: IStateManager<CNonceState>
  accessTokenSignerCallback?: JWTSignerCallback
}

export const tokenRequestEndpoint = (opts?: ITokenEndpointOpts): Router => {
  const tokenPath = opts?.tokenPath ?? process.env.TOKEN_PATH ?? '/token'
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
  router.post(
    tokenPath,
    handleHTTPStatus400({ stateManager: opts.stateManager }),
    handleTokenRequest({
      accessTokenSignerCallback: opts.accessTokenSignerCallback,
      nonceStateManager: opts.nonceStateManager,
      cNonceExpiresIn,
      interval,
      tokenExpiresIn,
    })
  )
  return router
}

const generateAccessToken = async (
  opts: Required<Pick<ITokenEndpointOpts, 'accessTokenSignerCallback' | 'tokenExpiresIn'> & { state: string }>
): Promise<string> => {
  const issuanceTime = new Date()
  const jwt: Jwt = {
    header: { typ: Typ.JWT, alg: Alg.ES256 },
    payload: { iat: issuanceTime.getTime(), exp: opts.tokenExpiresIn, iss: opts.state },
  }
  return await opts.accessTokenSignerCallback(jwt)
}

const handleTokenRequest = (
  opts: Required<Pick<ITokenEndpointOpts, 'cNonceExpiresIn' | 'interval' | 'accessTokenSignerCallback' | 'nonceStateManager' | 'tokenExpiresIn'>>
) => {
  return async (request: Request, response: Response) => {
    response.set({
      'Cache-Control': 'no-store',
      Pragma: 'no-cache',
    })

    const cNonce = v4()
    await opts.nonceStateManager?.setState(cNonce, { cNonce, createdOn: +new Date() })
    setTimeout(() => {
      opts.nonceStateManager?.deleteState(cNonce)
    }, opts.cNonceExpiresIn as number)

    const access_token = await generateAccessToken({
      tokenExpiresIn: opts.tokenExpiresIn,
      accessTokenSignerCallback: opts.accessTokenSignerCallback,
      state: request.body.state,
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
  if (assertedState.credentialOffer.grants) {
    // TODO implement authorization_code
    return Object.keys(assertedState.credentialOffer?.grants).includes(GrantType.PRE_AUTHORIZED_CODE) && grantType === GrantType.PRE_AUTHORIZED_CODE
  }
  return false
}

export const handleHTTPStatus400 = (opts: Required<Pick<ITokenEndpointOpts, 'stateManager'>>) => {
  return async (request: Request, response: Response, next: NextFunction) => {
    // TODO invalid_client: the client tried to send a Token Request with a Pre-Authorized Code without Client ID but the Authorization Server does not support anonymous access
    const assertedState = (await opts.stateManager.getAssertedState(request.body.state)) as CredentialOfferState
    await opts.stateManager.setState(request.body.state, assertedState)
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
      if (assertedState.credentialOffer.grants?.[GrantType.PRE_AUTHORIZED_CODE]?.user_pin_required && !request.body.user_pin) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_request, error_description: USER_PIN_REQUIRED_ERROR })
      }
      /*
      invalid_request:
      the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN
       */
      if (!assertedState.credentialOffer.grants?.[GrantType.PRE_AUTHORIZED_CODE]?.user_pin_required && request.body.user_pin) {
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
        request.body[PRE_AUTH_CODE_LITERAL] !== assertedState.credentialOffer.grants?.[GrantType.PRE_AUTHORIZED_CODE]?.[PRE_AUTH_CODE_LITERAL]
      ) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_grant, error_message: INVALID_PRE_AUTHORIZED_CODE })
      } else if (isPreAuthorizedCodeExpired(assertedState)) {
        return response.status(400).json({ error: TokenErrorResponse.invalid_grant, error_message: EXPIRED_PRE_AUTHORIZED_CODE })
      }
    }
    return next()
  }
}

const isPreAuthorizedCodeExpired = (state: CredentialOfferState) => {
  const now = +new Date()
  const expirationTime = state.createdOn + state.preAuthorizedCodeExpiresIn
  return now >= expirationTime
}
