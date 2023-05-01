import { KeyObject } from 'crypto'

import { AccessTokenResponse, Alg, CNonceState, CredentialOfferState, IStateManager, JWTHeader, JWTPayload, Typ } from '@sphereon/openid4vci-common'
import express, { NextFunction, Request, Response, Router } from 'express'
import * as jose from 'jose'
import { v4 } from 'uuid'

const router = express.Router()

interface ITokenEndpointOpts {
  tokenPath?: string
  interval?: number
  cNonceExpiresIn?: number
  tokenExpiresIn?: number
  stateManager?: IStateManager<CredentialOfferState>
  nonceStateManager?: IStateManager<CNonceState>
  privateKey: KeyObject
}

let tokenPath: string
let interval: number
let cNonceExpiresIn: number
let tokenExpiresIn: number
let stateManager: IStateManager<CredentialOfferState>
let nonceStateManager: IStateManager<CNonceState>
let privateKey: KeyObject

export const tokenRequestEndpoint = (opts?: ITokenEndpointOpts): Router => {
  tokenPath = (opts?.tokenPath ? opts.tokenPath : (process.env.TOKEN_PATH as string)) ?? '/token'
  interval = (opts?.interval ? opts.interval : parseInt(process.env.INTERVAL as string)) ?? 300000
  cNonceExpiresIn = (opts?.cNonceExpiresIn ? opts.cNonceExpiresIn : parseInt(process.env.C_NONCE_EXPIRES_IN as string)) ?? 300000
  tokenExpiresIn = (opts?.tokenExpiresIn ? opts.tokenExpiresIn : parseInt(process.env.TOKEN_EXPIRES_IN as string)) ?? 300000
  privateKey = opts?.privateKey as KeyObject
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

  const cNonce = v4()
  await nonceStateManager.setState(cNonce, { cNonce, createdOn: +new Date() })
  setTimeout(() => {
    nonceStateManager.deleteState(cNonce)
  }, cNonceExpiresIn)

  const issuanceTime = new Date()
  const header: JWTHeader = { typ: Typ.JWT, alg: Alg.ES256 }
  const payload: JWTPayload = { iat: issuanceTime.getTime(), exp: +new Date(issuanceTime.getTime() + tokenExpiresIn) }
  const access_token = await new jose.SignJWT({ ...payload }).setProtectedHeader({ ...header }).sign(privateKey)
  const responseBody: AccessTokenResponse = {
    access_token,
    token_type: 'bearer',
    expires_in: tokenExpiresIn,
    c_nonce: cNonce,
    c_nonce_expires_in: cNonceExpiresIn,
    interval,
  }
  return response.status(200).json(responseBody)
}

export const handleHTTPStatus400 = async (request: Request, response: Response, next: NextFunction) => {
  const assertedState = (await stateManager.getAssertedState(request.body.state)) as CredentialOfferState
  await stateManager.setState(request.body.state, assertedState)
  // TODO invalid_client: the client tried to send a Token Request with a Pre-Authorized Code without Client ID but the Authorization Server does not support anonymous access
  if (request.body.grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
    if (!request.body['pre-authorized_code']) {
      return response.status(400).json({ error: 'invalid_request', error_description: 'pre-authorized_code is required' })
    }
    /*
    invalid_request:
    the Authorization Server expects a PIN in the pre-authorized flow but the client does not provide a PIN
     */
    if (assertedState.userPinRequired && !request.body.user_pin) {
      return response.status(400).json({ error: 'invalid_request', error_description: 'User pin is required' })
    }
    /*
    invalid_request:
    the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN
     */
    if (!assertedState.userPinRequired && request.body.user_pin) {
      return response.status(400).json({ error: 'invalid_request', error_description: 'User pin is not required' })
    }
    /*
    invalid_grant:
    the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN
    the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
     */
    if (!/[0-9{,8}]/.test(request.body.user_pin)) {
      return response.status(400).json({ error: 'invalid_grant', error_message: 'PIN must consist of maximum 8 numeric characters' })
    }
    const now = +new Date()
    const expirationTime = assertedState.preAuthorizedCodeCreatedOn + assertedState.preAuthorizedCodeExpiresIn
    if (
      request.body.user_pin !== assertedState.pinCode ||
      request.body['pre-authorized_code'] !== assertedState['pre-authorized_code'] ||
      now >= expirationTime
    ) {
      return response.status(400).json({ error: 'invalid_grant', error_message: 'PIN is invalid or pre-authorized_code is invalid or expired' })
    }
  }
  return next()
}
