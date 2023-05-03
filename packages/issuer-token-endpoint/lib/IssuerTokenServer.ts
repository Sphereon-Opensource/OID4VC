import process from 'process'

import { CNonceState, CredentialOfferState, getNumberOrUndefined, IStateManager, JWTSignerCallback } from '@sphereon/openid4vci-common'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import * as dotenv from 'dotenv-flow'
import express, { Express } from 'express'

import { tokenRequestEndpoint } from './IssuerTokenEndpoint'

export class IssuerTokenServer {
  public readonly _app: Express
  private readonly _baseUrl: URL

  constructor(opts?: {
    app?: Express
    tokenExpiresIn?: number
    cNonceExpiresIn?: number
    interval?: number
    tokenPath?: string
    stateManager?: IStateManager<CredentialOfferState>
    nonceStateManager?: IStateManager<CNonceState>
    baseUrl?: string
    jwtSignerCallback?: JWTSignerCallback
  }) {
    dotenv.config()
    const { tokenPath, interval, tokenExpiresIn, cNonceExpiresIn, stateManager, nonceStateManager, jwtSignerCallback } = { ...opts }
    this._baseUrl = new URL(opts?.baseUrl ?? process.env.BASE_URL ?? 'http://localhost')

    if (!opts?.app) {
      this._app = express()
      const httpPort = getNumberOrUndefined(this._baseUrl.host.split(':')[1]) ?? getNumberOrUndefined(process.env.PORT) ?? 3000
      const host = this._baseUrl.host.split(':')[0]
      const secret = process.env.COOKIE_SIGNING_KEY

      this._app.use(cors())
      this._app.use(bodyParser.urlencoded({ extended: true }))
      this._app.use(bodyParser.json())
      this._app.use(cookieParser(secret))

      this._app.listen(httpPort, host, () => console.log(`HTTP server listening on port ${httpPort}`))
    } else {
      this._app = opts.app
    }
    this._app.use(
      this._baseUrl.pathname,
      tokenRequestEndpoint({ tokenPath, tokenExpiresIn, interval, cNonceExpiresIn, stateManager, nonceStateManager, jwtSignerCallback })
    )
  }
}
