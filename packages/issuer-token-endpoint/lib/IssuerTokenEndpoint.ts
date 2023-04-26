import * as process from 'process'

import {
  AccessTokenResponse,
  CNonceState,
  CredentialFormatEnum,
  CredentialOfferState,
  CredentialSupported,
  Display,
  IssuerCredentialSubjectDisplay,
  IssuerMetadata,
  IStateManager,
} from '@sphereon/openid4vci-common'
import { CredentialSupportedBuilderV1_11, VcIssuer, VcIssuerBuilder } from '@sphereon/openid4vci-issuer'
import { MemoryCNonceStateManager } from '@sphereon/openid4vci-issuer/dist/state-manager'
import { MemoryCredentialOfferStateManager } from '@sphereon/openid4vci-issuer/dist/state-manager/MemoryCredentialOfferStateManager'
import bodyParser from 'body-parser'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import * as dotenv from 'dotenv-flow'
import { Express, Request, Response } from 'express'
import { v4 } from 'uuid'

function buildVCIFromEnvironment() {
  const credentialsSupported: CredentialSupported = new CredentialSupportedBuilderV1_11()
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
    .withInMemoryCredentialOfferState()
    .build()
}

export class IssuerTokenEndpoint {
  public readonly express: Express
  private _vcIssuer: VcIssuer
  private readonly tokenExpiresIn: number
  private readonly cNonceExpiresIn: number
  constructor(opts?: {
    metadata: IssuerMetadata
    stateManager: IStateManager<CredentialOfferState>
    nonceManager: IStateManager<CNonceState>
    userPinRequired: boolean
    tokenExpiresIn?: number
    cNonceExpiresIn?: number
    express?: Express
  }) {
    dotenv.config()
    this.tokenExpiresIn = opts?.tokenExpiresIn ? opts.tokenExpiresIn : parseInt(process.env.TOKEN_EXPIRES_IN)
    this.cNonceExpiresIn = opts?.cNonceExpiresIn ? opts.cNonceExpiresIn : parseInt(process.env.C_NONCE_EXPIRES_IN)
    // todo: we probably want to pass a dummy issuance callback function here
    this._vcIssuer = opts
      ? (this._vcIssuer = new VcIssuer(opts.metadata, {
          userPinRequired: opts.userPinRequired,
          stateManager: opts.stateManager ?? new MemoryCredentialOfferStateManager(),
          nonceManager: opts.nonceManager ?? new MemoryCNonceStateManager(),
        }))
      : buildVCIFromEnvironment()
    if (!_express) {
      this.express = express()
      const port = process.env.PORT || 3000
      const secret = process.env.COOKIE_SIGNING_KEY

      this.express.use(cors())
      this.express.use(bodyParser.urlencoded({ extended: true }))
      this.express.use(bodyParser.json())
      this.express.use(cookieParser(secret))

      this.express.listen(port, () => console.log(`HTTP server listening on port ${port}`))
    } else {
      this._express = _express
    }
    this.registerTokenEndpoint()
  }

  private registerTokenEndpoint() {
    this._express.post('/token', (request: Request, response: Response) => {
      response.set({
        'Cache-Control': 'no-store',
        Pragma: 'no-cache',
      })
      if (request.body.grant_type === 'urn:ietf:params:oauth:grant-type:pre-authorized_code') {
        if (!request.body['pre-authorized_code']) {
          throw new Error('pre-authorized_code is required')
        }
        if (this._vcIssuer._userPinRequired && !request.body.user_pin) {
          throw new Error('User pin is required')
        }
        if (!/[0-9{,8}]/.test(request.body.user_pin)) {
          throw Error('PIN must consist of maximum 8 numeric characters')
        }
      }
      const cNonce = v4()
      this._vcIssuer.nonceStateManager.setState(cNonce, { cNonce, createdOn: +new Date() })
      setTimeout(() => {
        this._vcIssuer.nonceStateManager.deleteState(cNonce)
      }, this.cNonceExpiresIn)

      const responseBody: AccessTokenResponse = {
        access_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..sHQ', // What should be in the JWT?
        token_type: 'bearer',
        expires_in: this.tokenExpiresIn,
        c_nonce: cNonce,
        c_nonce_expires_in: this.cNonceExpiresIn,
      }
      return response.status(200).json(responseBody)
    })
  }
}
