import { KeyObject } from 'crypto'
import process from 'process'

import { CNonceState, CredentialOfferState, IStateManager } from '@sphereon/openid4vci-common'
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
    privateKey?: KeyObject
  }) {
    dotenv.config()
    const { tokenPath, interval, tokenExpiresIn, cNonceExpiresIn, stateManager, nonceStateManager, privateKey } = { ...opts }
    this._baseUrl = new URL((opts?.baseUrl ? opts.baseUrl : process.env.BASE_URL) ?? 'http://localhost')

    if (!privateKey) {
      throw new Error('Please provide a private key')
    }

    if (!opts?.app) {
      this._app = express()
      const port = this._baseUrl.host.split(':')[1] ? parseInt(this._baseUrl.host.split(':')[1]) : undefined
      const httpPort = (port ? port : process.env.PORT ? parseInt(process.env.PORT as string) : undefined) ?? 80
      const secret = process.env.COOKIE_SIGNING_KEY

      this._app.use(cors())
      this._app.use(bodyParser.urlencoded({ extended: true }))
      this._app.use(bodyParser.json())
      this._app.use(cookieParser(secret))

      this._app.listen(httpPort, this._baseUrl.host.split(':')[0], () => console.log(`HTTP server listening on port ${port}`))
    } else {
      this._app = opts.app
    }
    this._app.use(
      this._baseUrl.pathname,
      tokenRequestEndpoint({ tokenPath, tokenExpiresIn, interval, cNonceExpiresIn, stateManager, nonceStateManager, privateKey })
    )
  }
}

export default new IssuerTokenServer()._app
