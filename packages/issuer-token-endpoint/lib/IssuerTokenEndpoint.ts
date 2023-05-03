import {
  AccessTokenResponse,
  Alg,
  CNonceState,
  CredentialOfferState,
  getNumberOrUndefined,
  IStateManager,
  Jwt,
  JWTSignerCallback,
  Typ,
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
  jwtSignerCallback?: JWTSignerCallback
}

let tokenPath: string
let interval: number
let cNonceExpiresIn: number
let tokenExpiresIn: number
let stateManager: IStateManager<CredentialOfferState>
let nonceStateManager: IStateManager<CNonceState>
let jwtSignerCallback: JWTSignerCallback

export const tokenRequestEndpoint = (opts?: ITokenEndpointOpts): Router => {
  tokenPath = opts?.tokenPath ?? process.env.TOKEN_PATH ?? '/token'
  interval = opts?.interval ?? getNumberOrUndefined(process.env.INTERVAL) ?? 300000
  cNonceExpiresIn = opts?.cNonceExpiresIn ?? getNumberOrUndefined(process.env.C_NONCE_EXPIRES_IN) ?? 300000
  tokenExpiresIn = opts?.tokenExpiresIn ?? getNumberOrUndefined(process.env.TOKEN_EXPIRES_IN) ?? 300000
  if (opts?.jwtSignerCallback) {
    jwtSignerCallback = opts.jwtSignerCallback
  } else {
    throw new Error('Please provide a private a JWT signer function')
  }
  if (opts?.stateManager) {
    stateManager = opts.stateManager
  } else {
    throw new Error('Unable to proceed without an StateManager instance')
  }
  if (opts.nonceStateManager) {
    nonceStateManager = opts.nonceStateManager
  } else {
    throw new Error('Unable to proceed without an NonceStateManager instance')
  }
  router.post(tokenPath, handleHTTPStatus400, handleTokenRequest)
  return router
}

const generateAccessToken = async (): Promise<string> => {
  const issuanceTime = new Date()
  const jwt: Jwt = {
    header: { typ: Typ.JWT, alg: Alg.ES256 },
    payload: { iat: issuanceTime.getTime(), exp: +new Date(issuanceTime.getTime() + tokenExpiresIn) },
  }
  return await jwtSignerCallback(jwt)
}

const handleTokenRequest = async (request: Request, response: Response) => {
  response.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
  })

  const cNonce = v4()
  await nonceStateManager.setState(cNonce, { cNonce, createdOn: +new Date() })
  setTimeout(() => {
    nonceStateManager.deleteState(cNonce)
  }, cNonceExpiresIn)

  const access_token = await generateAccessToken()
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

export const handleHTTPStatus400 = async (request: Request, response: Response, next: NextFunction) => {
  // TODO invalid_client: the client tried to send a Token Request with a Pre-Authorized Code without Client ID but the Authorization Server does not support anonymous access
  const assertedState = (await stateManager.getAssertedState(request.body.state)) as CredentialOfferState
  await stateManager.setState(request.body.state, assertedState)
  if (request.body.grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    if (!request.body['pre-authorized_code']) {
      return response.status(400).json({ error: 'invalid_request', error_description: 'pre-authorized_code is required' })
    }
    /*
    invalid_request:
    the Authorization Server expects a PIN in the pre-authorized flow but the client does not provide a PIN
     */
    if (assertedState.credentialOffer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.user_pin_required && !request.body.user_pin) {
      return response.status(400).json({ error: 'invalid_request', error_description: 'User pin is required' })
    }
    /*
    invalid_request:
    the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN
     */
    if (!assertedState.credentialOffer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.user_pin_required && request.body.user_pin) {
      return response.status(400).json({ error: 'invalid_request', error_description: 'User pin is not required' })
    }
    /*
    invalid_grant:
    the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN
    the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
     */
    if ((request.body.user_pin && !/[0-9{,8}]/.test(request.body.user_pin)) || assertedState.userPin != getNumberOrUndefined(request.body.user_pin)) {
      return response.status(400).json({ error: 'invalid_grant', error_message: 'PIN must consist of maximum 8 numeric characters' })
    }

    if (getNumberOrUndefined(request.body.user_pin) !== assertedState.userPin) {
      return response.status(400).json({ error: 'invalid_grant', error_message: 'PIN is invalid' })
    } else if (
      request.body['pre-authorized_code'] !==
      assertedState.credentialOffer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.['pre-authorized_code']
    ) {
      return response.status(400).json({ error: 'invalid_grant', error_message: 'pre-authorized_code is invalid' })
    } else if (isPreAuthorizedCodeExpired(assertedState)) {
      return response.status(400).json({ error: 'invalid_grant', error_message: 'pre-authorized_code is expired' })
    }
  }
  return next()
}

const isPreAuthorizedCodeExpired = (state: CredentialOfferState) => {
  const now = +new Date()
  const expirationTime = state.createdOn + state.preAuthorizedCodeExpiresIn
  return now >= expirationTime
}
