import * as fs from 'fs'
import https from 'https'
import * as path from 'path'

import {
  CredentialFormatEnum,
  CredentialIssuerMetadataSupportedCredentials,
  CredentialRequest,
  Display,
  ICredentialOfferStateManager,
  IssuerCredentialSubjectDisplay,
  IssuerMetadata,
} from '@sphereon/openid4vci-common'
import { createCredentialOfferDeeplink, CredentialSupportedV1_11Builder, VcIssuer, VcIssuerBuilder } from '@sphereon/openid4vci-issuer'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import * as dotenv from 'dotenv-flow'
import express, { Express, Response } from 'express'
import { v4 as uuidv4 } from 'uuid'

const key = fs.readFileSync(process.env.PRIVATE_KEY || path.join(__dirname, './privkey.pem'), 'utf-8')
const cert = fs.readFileSync(process.env.x509_CERTIFICATE || path.join(__dirname, './chain.pem'), 'utf-8')

function buildVCIFromEnvironment() {
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
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  private tokenToId: Map<string, string> = new Map()

  constructor(opts?: { metadata: IssuerMetadata; stateManager: ICredentialOfferStateManager; userPinRequired: boolean }) {
    dotenv.config()
    this._vcIssuer = opts ? (this._vcIssuer = new VcIssuer(opts.metadata, opts.stateManager, opts.userPinRequired)) : buildVCIFromEnvironment()
    this.express = express()
    const port = process.env.PORT || 3443
    const secret = process.env.COOKIE_SIGNING_KEY

    this.express.use(cors())
    this.express.use(bodyParser.urlencoded({ extended: true }))
    this.express.use(bodyParser.json())
    this.express.use(cookieParser(secret))

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
}

export default new RestAPI().express
