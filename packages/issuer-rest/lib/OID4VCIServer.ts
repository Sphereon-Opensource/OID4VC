import http from 'http'
import process from 'process'

import {
  ACCESS_TOKEN_ISSUER_REQUIRED_ERROR,
  AuthorizationRequestV1_0_09,
  CredentialFormat,
  CredentialSupported,
  getNumberOrUndefined,
  IssuerCredentialSubjectDisplay,
  JWT_SIGNER_CALLBACK_REQUIRED_ERROR,
} from '@sphereon/oid4vci-common'
import { CredentialSupportedBuilderV1_11, VcIssuer, VcIssuerBuilder } from '@sphereon/oid4vci-issuer'
import bodyParser from 'body-parser'
import cors from 'cors'
import * as dotenv from 'dotenv-flow'
import express, { Express, NextFunction, Request, Response } from 'express'
import { v4 as uuidv4 } from 'uuid'

import { handleHTTPStatus400, handleTokenRequest, ITokenEndpointOpts } from './IssuerTokenEndpoint'
import { sendErrorResponse, validateRequestBody } from './expressUtils'

const expiresIn = process.env.EXPIRES_IN ? parseInt(process.env.EXPIRES_IN) : 90

function buildVCIFromEnvironment() {
  const credentialsSupported: CredentialSupported = new CredentialSupportedBuilderV1_11()
    .withCryptographicSuitesSupported(process.env.cryptographic_suites_supported as string)
    .withCryptographicBindingMethod(process.env.cryptographic_binding_methods_supported as string)
    .withFormat(process.env.credential_supported_format as unknown as CredentialFormat)
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
    })
    .withIssuerCredentialSubjectDisplay(
      process.env.credential_subject_display_key1 as string,
      {
        name: process.env.credential_subject_display_key1_name as string,
        locale: process.env.credential_subject_display_key1_locale as string,
      } as IssuerCredentialSubjectDisplay // fixme: This is wrong (remove the cast and see it has no matches)
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
    .withInMemoryCNonceState()
    .build()
}

export class OID4VCIServer {
  // public readonly express: Express
  private readonly _vcIssuer: VcIssuer
  private authRequestsData: Map<string, AuthorizationRequestV1_0_09> = new Map()
  private readonly _app: Express
  private readonly _baseUrl: URL
  private readonly _server: http.Server

  public get app(): Express {
    return this._app
  }

  public get server(): http.Server {
    return this._server
  }

  constructor(opts?: {
    issuer?: VcIssuer // If not supplied as argument, it will be fully configured from environment variables
    tokenEndpointDisabled?: boolean // Disable if used in an existing OAuth2/OIDC environment and have the AS handle tokens
    tokenEndpointOpts?: ITokenEndpointOpts
    serverOpts?: {
      app?: Express
      port?: number
      baseUrl?: string
    }
  }) {
    dotenv.config()

    this._baseUrl = new URL(opts?.serverOpts?.baseUrl ?? process.env.BASE_URL ?? 'http://localhost')
    // fixme: this is way too naive (fails for instance for base urls with a path)
    const httpPort = getNumberOrUndefined(this._baseUrl.host.split(':')[1]) ?? getNumberOrUndefined(process.env.PORT) ?? 3000
    const host = this._baseUrl.host.split(':')[0]

    if (!opts?.serverOpts?.app) {
      this._app = express()
      this.app.use(cors())
      this.app.use(bodyParser.urlencoded({ extended: true }))
      this.app.use(bodyParser.json())
      // this._app.use(cookieParser(secret))
    } else {
      this._app = opts.serverOpts.app
    }
    this._vcIssuer = opts?.issuer ? opts.issuer : buildVCIFromEnvironment()

    const tokenEndpointDisabled = opts?.tokenEndpointDisabled === true || process.env.TOKEN_ENDPOINT_DISABLED === 'true'

    this.pushedAuthorizationEndpoint()
    this.metadataEndpoint()
    this.credentialEndpoint()
    this.credentialOffersEndpoint()
    if (tokenEndpointDisabled) {
      console.log('Token endpoint disabled by configuration')
    } else {
      this.accessTokenEndpoint(opts?.tokenEndpointOpts)
    }
    this._server = this.app.listen(httpPort, host, () => console.log(`HTTP server listening on port ${httpPort}`))
  }

  private accessTokenEndpoint(tokenEndpointOpts?: ITokenEndpointOpts) {
    const path = tokenEndpointOpts?.tokenPath ?? process.env.TOKEN_PATH ?? '/token'
    const accessTokenIssuer = tokenEndpointOpts?.accessTokenIssuer ?? process.env.ACCESS_TOKEN_ISSUER

    const preAuthorizedCodeExpirationDuration =
      tokenEndpointOpts?.preAuthorizedCodeExpirationDuration ?? getNumberOrUndefined(process.env.PRE_AUTHORIZED_CODE_EXPIRATION_DURATION) ?? 300000
    const interval = tokenEndpointOpts?.interval ?? getNumberOrUndefined(process.env.INTERVAL) ?? 300000
    const tokenExpiresIn = tokenEndpointOpts?.tokenExpiresIn ?? 300

    // todo: this means we cannot sign JWTs or issue access tokens when configured from env vars!
    if (!tokenEndpointOpts?.accessTokenSignerCallback) {
      throw new Error(JWT_SIGNER_CALLBACK_REQUIRED_ERROR)
    } else if (!accessTokenIssuer) {
      throw new Error(ACCESS_TOKEN_ISSUER_REQUIRED_ERROR)
    }
    this.app.post(
      path,
      handleHTTPStatus400({
        credentialOfferSessionManager: this.vcIssuer.credentialOfferSessions,
        preAuthorizedCodeExpirationDuration,
      }),
      handleTokenRequest({
        accessTokenSignerCallback: tokenEndpointOpts.accessTokenSignerCallback,
        nonceManager: this.vcIssuer.cNonces,
        cNonceExpiresIn: this.vcIssuer.cNonceExpiresIn,
        interval,
        tokenExpiresIn,
        accessTokenIssuer,
      })
    )
  }

  private metadataEndpoint() {
    this.app.get('/metadata', (request: Request, response: Response) => {
      return response.send(this.vcIssuer.issuerMetadata)
    })
  }

  private credentialEndpoint() {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    this.app.get('/credential', async (request: Request, _response: Response) => {
      if (!request.body)
        this.vcIssuer.issueCredentialFromIssueRequest({
          issueCredentialRequest: request.body.issueCredentialRequest,
          issuerState: request.body.issuerState,
          jwtVerifyCallback: request.body.jwtVerifyCallback,
          issuerCallback: request.body.issuerCallback,
          cNonce: request.body.cNonce,
        })
    })
  }

  private credentialOffersEndpoint() {
    this.app.get('/credential-offers/:id', async (request: Request, response: Response) => {
      const { id } = request.params
      try {
        const credOfferSession = await this.vcIssuer.credentialOfferSessions.get(id)
        if (!credOfferSession || !credOfferSession.credentialOffer) {
          return sendErrorResponse(response, 404, {
            error: 'invalid_request',
            error_description: `Credential offer ${id} not found`,
          })
        }
        return response.send(JSON.stringify(credOfferSession.credentialOffer.credential_offer))
      } catch (e) {
        return sendErrorResponse(
          response,
          500,
          {
            error: 'invalid_request',
            error_description: (e as Error).message,
          },
          e
        )
      }
    })
  }

  private pushedAuthorizationEndpoint() {
    const handleHttpStatus400 = async (req: Request, res: Response, next: NextFunction) => {
      if (!req.body) {
        return res.status(400).send({ error: 'invalid_request', error_description: 'Request body must be present' })
      }
      const required = ['client_id', 'code_challenge_method', 'code_challenge', 'redirect_uri']
      const conditional = ['authorization_details', 'scope']
      try {
        validateRequestBody({ required, conditional, body: req.body })
      } catch (e: unknown) {
        return sendErrorResponse(res, 400, {
          error: 'invalid_request',
          error_description: (e as Error).message,
        })
      }
      return next()
    }

    this.app.post('/par', handleHttpStatus400, (req: Request, res: Response) => {
      // FIXME Fake client for testing, it needs to come from a registered client
      const client = {
        scope: ['openid', 'test'],
        redirectUris: ['http://localhost:8080/*', 'https://www.test.com/*', 'https://test.nl', 'http://*/chart', 'http:*'],
      }

      // For security reasons the redirect_uri from the request needs to be matched against the ones present in the registered client
      const matched = client.redirectUris.filter((s: string) => new RegExp(s.replace('*', '.*')).test(req.body.redirect_uri))
      if (!matched.length) {
        return sendErrorResponse(res, 400, {
          error: 'invalid_request',
          error_description: 'redirect_uri is not valid for the given client',
        })
      }

      // The scopes from the request need to be matched against the ones present in the registered client
      if (!req.body.scope.split(',').every((scope: string) => client.scope.includes(scope))) {
        return sendErrorResponse(res, 400, {
          error: 'invalid_scope',
          error_description: 'scope is not valid for the given client',
        })
      }

      //TODO Implement authorization_details verification

      // TODO: Both UUID and requestURI need to be configurable for the server
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

  get vcIssuer(): VcIssuer {
    return this._vcIssuer
  }
}
