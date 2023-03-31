import * as fs from 'fs'
import * as https from 'https'
import * as path from 'path'

import { AuthorizationRequest } from '@sphereon/openid4vci-common'
import * as bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import * as dotenv from 'dotenv-flow'
import express, { Express, NextFunction, Request, Response } from 'express'
import { v4 as uuidv4 } from 'uuid'

import { validateRequestBody } from './expressUtils'

const key = fs.readFileSync(path.join(__dirname, process.env.PRIVATE_KEY || './privkey.pem'), 'utf-8')
const cert = fs.readFileSync(path.join(__dirname, process.env.x509_CERTIFICATE || './chain.pem'), 'utf-8')
const expiresIn = process.env.EXPIRES_IN ? parseInt(process.env.EXPIRES_IN) : 90

export class AuthServer {
  public readonly app: Express
  private authRequestsData: Map<string, AuthorizationRequest> = new Map()

  constructor() {
    dotenv.config()
    this.app = express()
    const httpsPort = process.env.PORT || 3443
    const secret = process.env.COOKIE_SIGNING_KEY

    this.app.use(cors())
    this.app.use(express.urlencoded({ extended: true }))
    this.app.use(bodyParser.json())
    this.app.use(cookieParser(secret))

    this.pushedAuthorizationEndpoint()
    const credentials = { key, cert }
    const httpsServer = https.createServer(credentials, this.app as any)
    httpsServer.listen(httpsPort as number, '0.0.0.0', () => console.log(`HTTPS server listening on port ${httpsPort}`))
  }

  private pushedAuthorizationEndpoint() {
    const handleHttpStatus400 = async (req: Request, res: Response, next: NextFunction) => {
      if (!req.body) {
        return res.status(400).send({ error: 'invalid_request', error_description: 'Request body must be present' })
      }
      const required = ['client_id', 'code_challenge_method', 'code_challenge', 'redirect_uri']
      const conditional = ['authorization_details', 'scope']
      const message = validateRequestBody({ required, conditional, body: req.body })
      if (message) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: message,
        })
      }
      return next()
    }

    this.app.post('/par', handleHttpStatus400, (req: Request, res: Response) => {
      // Fake client for testing, it needs to come from a registered client
      const client = {
        scope: ['openid', 'test'],
        redirectUris: ['http://localhost:8080/*', 'https://www.test.com/*', 'https://test.nl', 'http://*/chart', 'http:*'],
      }

      // For security reasons the redirect_uri from the request needs to be matched against the ones present in the registered client
      const matched = client.redirectUris.filter((s: string) => new RegExp(s.replace('*', '.*')).test(req.body.redirect_uri))
      if (!matched.length) {
        return res.status(400).send({ error: 'invalid_request', error_description: 'redirect_uri is not valid for the given client' })
      }

      // The scopes from the request need to be matched against the ones present in the registered client
      if (!req.body.scope.split(',').every((scope: string) => client.scope.includes(scope))) {
        return res.status(400).send({ error: 'invalid_scope', error_description: 'scope is not valid for the given client' })
      }

      //TODO Implement authorization_details verification

      const uuid = uuidv4()
      const requestUri = `urn:ietf:params:oauth:request_uri:${uuid}`
      // The redirect_uri is created and set in a map, to keep track of the actual request
      this.authRequestsData.set(requestUri, req.body)
      // Invalidates the request_uri removing it from the mapping after it is expired, needs to be refactored because
      // some of the properties will be needed in subsequent steps if the authorization succeeds
      // TODO in the /token endpoint the code_challenge must be matched against the hashed code_verifier
      setTimeout(() => {
        this.authRequestsData.delete(requestUri)
      }, expiresIn * 1000)

      return res.status(201).json({ request_uri: requestUri, expires_in: expiresIn })
    })
  }
}
export default new AuthServer().app
