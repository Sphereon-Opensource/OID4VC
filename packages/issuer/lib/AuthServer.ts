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
        res.status(400).send({ error: 'invalid_request', error_description: 'Request body must be present' })
      }
      const required = ['client_id', 'code_challenge_method', 'code_challenge', 'redirect_uri']
      const conditional = ['authorization_details', 'scope']
      const message = validateRequestBody({ required, conditional, body: req.body })
      if (message) {
        res.status(400).json({
          error: 'invalid_request',
          error_description: message,
        })
      }
      next()
    }

    this.app.post('/par', handleHttpStatus400, (req: Request, res: Response) => {
      // Fake client for testing
      const client = {
        scope: ['openid', 'test'],
        redirectUris: ['http://localhost:8080/*', 'https://www.test.com/*', 'https://test.nl', 'http://*/chart'],
      }

      const matched = client.redirectUris.filter((s: string) => new RegExp(s.replace('*', '.*')).test(req.body.redirect_uri))
      if (!matched.length) {
        res.status(400).send({ error: 'invalid_request', error_description: 'redirect_uri is not valid for the given client' })
      }

      if (!req.body.scope.split(',').every((scope: string) => client.scope.includes(scope))) {
        res.status(400).send({ error: 'invalid_scope', error_description: 'scope is not valid for the given client' })
      }

      //TODO Implement authorization_details verification

      const uuid = uuidv4()
      const requestUri = `urn:ietf:params:oauth:request_uri:${uuid}`
      this.authRequestsData.set(requestUri, req.body)
      // Invalidates the request_uri removing it from the mapping
      setTimeout(() => {
        this.authRequestsData.delete(requestUri)
      }, expiresIn * 1000)

      res.status(201).json({ request_uri: requestUri, expires_in: expiresIn })
    })
  }
}
export default new AuthServer().app
