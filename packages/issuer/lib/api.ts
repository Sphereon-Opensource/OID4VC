import * as fs from 'fs'
import https from 'https'
import * as path from 'path'

import {
  AuthorizationRequest,
  CredentialFormatEnum,
  CredentialIssuerMetadataSupportedCredentials,
  CredentialRequest,
  Display,
  IssuerCredentialSubjectDisplay,
} from '@sphereon/openid4vci-common'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import * as dotenv from 'dotenv-flow'
import express, { Express, NextFunction, Request, Response } from 'express'
import { v4 as uuidv4 } from 'uuid'

import { VcIssuer } from './VcIssuer'
import { CredentialSupportedV1_11Builder, VcIssuerBuilder } from './builder'
import { validateRequestBody } from './expressUtils'
import { createCredentialOfferDeeplink } from './functions'

const key = fs.readFileSync(path.join(__dirname, process.env.PRIVATE_KEY || './privkey.pem'), 'utf-8')
const cert = fs.readFileSync(path.join(__dirname, process.env.x509_CERTIFICATE || './chain.pem'), 'utf-8')
const expiresIn = process.env.EXPIRES_IN ? parseInt(process.env.EXPIRES_IN) : 90

function buildVcIssuer() {
  const credentialsSupported: CredentialIssuerMetadataSupportedCredentials = new CredentialSupportedV1_11Builder()
    .withCryptographicSuitesSupported(process.env.cryptographic_suites_supported as string)
    .withCryptographicBindingMethod(process.env.cryptographic_binding_methods_supported as string)
    .withFormat(process.env.credential_supported_format as unknown as CredentialFormatEnum)
    .withId(process.env.credential_supported_id as string)
    .withTypes([process.env.credential_supported_types_1 as string, process.env.credential_supported_types_2 as string])
    .withCredentialDisplay({
      name: process.env.credential_display_name as string,
      locale: process.env.credential_display_locale as string,
      logo: {
        url: process.env.credential_display_logo_url as string,
        alt_text: process.env.credential_display_logo_alt_text as string,
      },
      background_color: process.env.credential_display_background_color as string,
      text_color: process.env.credential_display_text_color as string,
    } as Display)
    .withIssuerCredentialSubjectDisplay(
      process.env.credential_subject_display_key1 as string,
      {
        name: process.env.credential_subject_display_key1_name as string,
        locale: process.env.credential_subject_display_key1_locale as string,
      } as IssuerCredentialSubjectDisplay
    )
    .build()
  return new VcIssuerBuilder()
    .withUserPinRequired(process.env.user_pin_required as unknown as boolean)
    .withAuthorizationServer(process.env.authorization_server as string)
    .withCredentialEndpoint(process.env.credential_endpoint as string)
    .withCredentialIssuer(process.env.credential_issuer as string)
    .withIssuerDisplay({
      name: process.env.issuer_name as string,
      locale: process.env.issuer_locale as string,
    })
    .withCredentialsSupported(credentialsSupported)
    .build()
}

export class RestAPI {
  public readonly express: Express
  private _vcIssuer: VcIssuer
  //fixme: use this map for now as an internal mechanism for preAuthorizedCode to ids
  private tokenToId: Map<string, string> = new Map()
  private authRequestsData: Map<string, AuthorizationRequest> = new Map()

  constructor() {
    dotenv.config()
    this._vcIssuer = buildVcIssuer()
    this.express = express()
    const port = process.env.PORT || 3443
    const secret = process.env.COOKIE_SIGNING_KEY

    this.express.use(cors())
    this.express.use(bodyParser.urlencoded({ extended: true }))
    this.express.use(bodyParser.json())
    this.express.use(cookieParser(secret))

    this.pushedAuthorizationEndpoint()
    this.registerMetadataEndpoint()
    this.registerTokenRequestEndpoint()
    this.registerCredentialRequestEndpoint()
    this.registerCredentialOfferEndpoint()
    const credentials = { key, cert }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const httpsServer = https.createServer(credentials, this.express as any)
    httpsServer.listen(port as number, '0.0.0.0', () => console.log(`HTTPS server listening on port ${port}`))
  }

  private static sendErrorResponse(response: Response, statusCode: number, message: string) {
    response.statusCode = statusCode
    response.status(statusCode).send(message)
  }

  private registerMetadataEndpoint() {
    this.express.get('/metadata', (request, response) => {
      return response.send(this._vcIssuer._issuerMetadata)
    })
  }
  private registerTokenRequestEndpoint() {
    this.express.post('/token', (request, response) => {
      return RestAPI.sendErrorResponse(response, 501, 'Not implemented')
    })
  }
  private registerCredentialRequestEndpoint() {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    this.express.get('/credential-request', async (request, _response) => {
      this._vcIssuer.issueCredentialFromIssueRequest(request as unknown as CredentialRequest)
    })
  }

  private registerCredentialOfferEndpoint() {
    this.express.get('/credential-offer/:pre_authorized_code', async (request, response) => {
      const preAuthorizedCode = request.params.pre_authorized_code
      const id = uuidv4()
      this.tokenToId.set(preAuthorizedCode, id)
      return response.send(createCredentialOfferDeeplink(preAuthorizedCode, this._vcIssuer._issuerMetadata))
    })
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

    this.express.post('/par', handleHttpStatus400, (req: Request, res: Response) => {
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

export default new RestAPI().express
