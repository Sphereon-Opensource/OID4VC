import * as bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import * as dotenv from 'dotenv-flow'
import express, { Express, Request, Response } from 'express'
import { v4 as uuidv4 } from "uuid";
import * as fs from 'fs'
import * as path from 'path'
import { AuthorizationRequest } from "@sphereon/openid4vci-common";
import * as http from 'http'
import * as https from 'https'
const key = fs.readFileSync(path.join(__dirname, process.env.PRIVATE_KEY || './privkey.pem'), 'utf-8')
const cert = fs.readFileSync(path.join(__dirname, process.env.x509_CERTIFICATE || './chain.pem'), 'utf-8')

export class AuthServer {
  public readonly app: Express
  private authRequestsData: Map<string, AuthorizationRequest> = new Map()

  constructor() {
    dotenv.config()
    this.app = express()
    const httpPort = process.env.PORT || 3080
    const httpsPort = process.env.PORT || 3443
    const secret = process.env.COOKIE_SIGNING_KEY

    this.app.use((req, res, next) => {
      res.header('Access-Control-Allow-Origin', '*')
      // Request methods you wish to allow
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE')

      // Request headers you wish to allow
      res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type')

      // Set to true if you need the website to include cookies in the requests sent
      // to the API (e.g. in case you use sessions)
      res.setHeader('Access-Control-Allow-Credentials', 'true')
      next()
    })
    this.app.use(express.urlencoded({ extended: true }))
    this.app.use(bodyParser.json())
    this.app.use(cookieParser(secret))

    this.pushedAuthorizationEndpoint()
    const credentials = { key, cert }
    const httpServer = http.createServer(this.app)
    const httpsServer = https.createServer(credentials, this.app as any)
    httpServer.listen(httpPort as number, '0.0.0.0', () => console.log(`HTTP server listening on port ${httpPort}`))
    httpsServer.listen(httpsPort as number, '0.0.0.0', () => console.log(`HTTPS server listening on port ${httpsPort}`))
  }

  private validateRequestBody({
      required,
      conditional,
      body
  }: { required?: string[], conditional?: string[], body: Pick<Request, 'body'>}): string | undefined {
    const keys = Object.keys(body)
    let message
    if (required && !required.every(k => keys.includes(k))) {
      message = `Request must contain ${required.toString()}`
    }
    if (conditional && !conditional.some(k => keys.includes(k))) {
      message = message ? `and request must contain ether ${conditional.toString()}`: `Request must contain ether ${conditional.toString()}`
    }
    return message
  }

  private pushedAuthorizationEndpoint() {
    this.app.post('/par', (req: Request, res: Response) => {
      // HTTP Status 400
      if (req.body) {
        const required = ['client_id', 'code_challenge_method', 'code_challenge', 'redirect_uri']
        const conditional = ['authorization_details', 'scope']
        const message = this.validateRequestBody({ required, conditional, body: req.body })
        if (message) {
          res.status(400).json({
            error: 'invalid_request',
            error_description: message
          })
        }
      } else {
        res.status(400).send({ error: 'invalid_request',
          error_description: 'Request body must be present'})
      }

      // Search for the registered client
      const client = {
        scope: ['openid', 'test'],
        redirectUris: ['http://localhost:8080/*', 'https://www.test.com/*', 'https://test.nl', 'http://*/chart']
      }

      const matched = client.redirectUris.filter((s: string) => new RegExp(s.replace('*', '.*')).test(req.body.redirect_uri))
      if (!matched.length) {
        res.status(400).send({ error: 'invalid_request',
          error_description: 'redirect_uri is not valid for the given client'})
      }

      if(!req.body.scope.split(',').every((scope: string) => client.scope.includes(scope))) {
        res.status(400).send({ error: 'invalid_scope',
          error_description: 'scope is not valid for the given client'})
      }

      // No need to process authorization_details at the moment
      const uuid = uuidv4()
      this.authRequestsData.set(uuid, req.body)

      res.status(201).json({ request_uri: `urn:ietf:params:oauth:request_uri:${uuid}`, expires_in: process.env.EXPIRES_IN || 90 })
    })
  }
}

export default new AuthServer().app
