import {
  CredentialFormatEnum,
  CredentialIssuerMetadataSupportedCredentials,
  CredentialRequest,
  Display,
  IssuerCredentialSubjectDisplay,
} from '@sphereon/openid4vci-common'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import * as dotenv from 'dotenv-flow'
import express, { Express, Response } from 'express'
import { v4 as uuidv4 } from 'uuid'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore

import { VcIssuer } from './VcIssuer'
import { CredentialSupportedV1_11Builder, VcIssuerBuilder } from './builder'
import { createCredentialOfferDeeplink } from './functions'

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
  public express: Express
  private _vcIssuer: VcIssuer
  //fixme: use this map for now as an internal mechanism for preAuthorizedCode to ids
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  private tokenToId: Map<string, string> = new Map()

  constructor() {
    dotenv.config()
    this._vcIssuer = buildVcIssuer()
    this.express = express()
    const port = process.env.PORT || 3000
    const secret = process.env.COOKIE_SIGNING_KEY

    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    this.express.use((req, res, next) => {
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
    this.express.use(bodyParser.urlencoded({ extended: true }))
    this.express.use(bodyParser.json())
    this.express.use(cookieParser(secret))
    this.express.listen(port as number, '0.0.0.0', () => console.log(`Listening on port ${port}`))
    this.registerMetadataEndpoint()
    this.registerTokenRequestEndpoint()
    this.registerCredentialRequestEndpoint()
    this.registerCredentialOfferEndpoint()
  }

  private static sendErrorResponse(response: Response, statusCode: number, message: string) {
    response.statusCode = statusCode
    response.status(statusCode).send(message)
  }

  private registerMetadataEndpoint() {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    this.express.get('/metadata', (request, response) => {
      return response.send(this._vcIssuer._issuerMetadata)
    })
  }
  private registerTokenRequestEndpoint() {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    this.express.post('/token', (request, response) => {
      return RestAPI.sendErrorResponse(response, 501, 'Not implemented')
    })
  }
  private registerCredentialRequestEndpoint() {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    this.express.get('/credential-request', async (request, response) => {
      this._vcIssuer.issueCredentialFromIssueRequest(request as unknown as CredentialRequest)
    })
  }

  private registerCredentialOfferEndpoint() {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    this.express.get('/credential-offer/:pre_authorized_code', async (request, response) => {
      const preAuthorizedCode = request.params.pre_authorized_code
      const id = uuidv4()
      this.tokenToId.set(preAuthorizedCode, id)
      return response.send(createCredentialOfferDeeplink(preAuthorizedCode, this._vcIssuer._issuerMetadata))
    })
  }
}

export default new RestAPI().express
