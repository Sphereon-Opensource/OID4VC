import { AccessTokenResponse, CNonceState, CredentialOfferState, IStateManager } from '@sphereon/openid4vci-common'
import express, { NextFunction, Request, Response, Router } from 'express'
import { v4 } from 'uuid'

const router = express.Router()

interface ITokenEndpointOpts {
  tokenPath?: string
  interval?: number
  cNonceExpiresIn?: number
  tokenExpiresIn?: number
  userPinRequired?: boolean
  stateManager?: IStateManager<CredentialOfferState>
  nonceStateManager?: IStateManager<CNonceState>
}

let tokenPath: string
let interval: number
let cNonceExpiresIn: number
let tokenExpiresIn: number
let userPinRequired: boolean
let stateManager: IStateManager<CredentialOfferState>
let nonceStateManager: IStateManager<CNonceState>

export const tokenRequestEndpoint = (opts?: ITokenEndpointOpts): Router => {
  tokenPath = (opts?.tokenPath ? opts.tokenPath : (process.env.TOKEN_PATH as string)) ?? '/token'
  interval = (opts?.interval ? opts.interval : parseInt(process.env.INTERVAL as string)) ?? 300000
  cNonceExpiresIn = (opts?.cNonceExpiresIn ? opts.cNonceExpiresIn : parseInt(process.env.C_NONCE_EXPIRES_IN as string)) ?? 300000
  tokenExpiresIn = (opts?.tokenExpiresIn ? opts.tokenExpiresIn : parseInt(process.env.TOKEN_EXPIRES_IN as string)) ?? 300000
  userPinRequired = (opts?.userPinRequired ? opts.userPinRequired : !!process.env.USER_PIN_REQUIRED) ?? false
  if (opts?.stateManager) {
    stateManager = opts.stateManager
  } else {
    throw new Error('Unable to proceed without an StateManager instance')
  }
  if (opts.nonceStateManager) {
    stateManager = opts.stateManager
  } else {
    throw new Error('Unable to proceed without an NonceStateManager instance')
  }
  router.post(tokenPath, handleHTTPStatus400, handleTokenRequest)
  return router
}

const handleTokenRequest = async (request: Request, response: Response) => {
  response.set({
    'Cache-Control': 'no-store',
    Pragma: 'no-cache',
  })

  const assertedState = (await stateManager.getAssertedState(request.body.state)) as CredentialOfferState
  assertedState!['pre-authorized_code'] = request.body['pre-authorized_code']
  await stateManager.setState(request.body.state, assertedState)

  const cNonce = v4()
  await nonceStateManager.setState(cNonce, { cNonce, createdOn: +new Date() })
  setTimeout(() => {
    nonceStateManager.deleteState(cNonce)
  }, cNonceExpiresIn)

  const responseBody: AccessTokenResponse = {
    access_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ', // What should be in the JWT?
    token_type: 'bearer',
    expires_in: tokenExpiresIn,
    c_nonce: cNonce,
    c_nonce_expires_in: cNonceExpiresIn,
    interval,
  }
  return response.status(200).json(responseBody)
}

export const handleHTTPStatus400 = (request: Request, response: Response, next: NextFunction) => {
  /*
  invalid_request:

the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN

the Authorization Server expects a PIN in the pre-authorized flow but the client does not provide a PIN
invalid_grant:

the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN

the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
invalid_client:

the client tried to send a Token Request with a Pre-Authorized Code without Client ID but the Authorization Server does not support anonymous access
   */
  if (request.body.grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    if (!request.body['pre-authorized_code']) {
      return response.status(400).json({ error: 'invalid_request', error_description: 'pre-authorized_code is required' })
    }
    if (userPinRequired && !request.body.user_pin) {
      return response.status(400).json({ error: 'invalid_request', error_description: 'User pin is required' })
    }
    if (!userPinRequired && request.body.user_pin) {
      return response.status(400).json({ error: 'invalid_request', error_description: 'User pin is not required' })
    }
    if (!/[0-9{,8}]/.test(request.body.user_pin)) {
      return response.status(400).json({ error: 'invalid_grant', error_message: 'PIN must consist of maximum 8 numeric characters' })
    }
  }
  return next()
}
