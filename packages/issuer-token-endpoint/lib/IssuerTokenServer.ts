import { KeyObject } from 'crypto'
import process from 'process'

import { Alg, CNonceState, CredentialOfferState, getNumberOrUndefined, IStateManager, Jwt, JWTSignerCallback } from '@sphereon/openid4vci-common'
import { MemoryCNonceStateManager, MemoryCredentialOfferStateManager } from '@sphereon/openid4vci-issuer/dist/state-manager'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import * as dotenv from 'dotenv-flow'
import express, { Express } from 'express'
import * as jose from 'jose'

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
    this._baseUrl = new URL((opts?.baseUrl ? opts.baseUrl : process.env.BASE_URL) ?? 'http://localhost')

    if (!opts?.app) {
      this._app = express()
      const port = getNumberOrUndefined(this._baseUrl.host.split(':')[1])
      const httpPort = (port ? port : getNumberOrUndefined(process.env.PORT)) ?? 3000
      const secret = process.env.COOKIE_SIGNING_KEY

      this._app.use(cors())
      this._app.use(bodyParser.urlencoded({ extended: true }))
      this._app.use(bodyParser.json())
      this._app.use(cookieParser(secret))

      this._app.listen(httpPort, this._baseUrl.host.split(':')[0], () => console.log(`HTTP server listening on port ${httpPort}`))
    } else {
      this._app = opts.app
    }
    this._app.use(
      this._baseUrl.pathname,
      tokenRequestEndpoint({ tokenPath, tokenExpiresIn, interval, cNonceExpiresIn, stateManager, nonceStateManager, jwtSignerCallback })
    )
  }
}

const signerCallback = async (jwt: Jwt, kid?: string): Promise<string> => {
  const privateKey = (await jose.generateKeyPair(Alg.ES256)).privateKey as KeyObject
  return new jose.SignJWT({ ...jwt.payload }).setProtectedHeader({ ...jwt.header }).sign(privateKey)
}

const state = new MemoryCredentialOfferStateManager()
state.setState('test_state', {
  userPinRequired: true,
  userPin: 493536,
  preAuthorizedCodeCreatedOn: +new Date(),
  preAuthorizedCodeExpiresIn: 300000,
  createdOn: +new Date(),
  credentialOffer: {
    credential_issuer: 'test_issuer',
    credential_definition: {
      '@context': ['test_context'],
      types: ['VerifiableCredential'],
      credentialSubject: {},
    },
  },
})
export default new IssuerTokenServer({
  stateManager: state,
  nonceStateManager: new MemoryCNonceStateManager(),
  jwtSignerCallback: signerCallback,
})._app
