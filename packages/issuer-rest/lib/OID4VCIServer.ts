import {
  AuthorizationRequest,
  ClientMetadata,
  CreateCredentialOfferURIResult,
  CredentialConfigurationSupportedV1_0_13,
  CredentialOfferMode,
  IssuerCredentialSubjectDisplay,
  OID4VCICredentialFormat,
  QRCodeOpts,
} from '@sphereon/oid4vci-common'
import {
  CredentialSupportedBuilderV1_13,
  ITokenEndpointOpts,
  oidcAccessTokenVerifyCallback,
  VcIssuer,
  VcIssuerBuilder,
} from '@sphereon/oid4vci-issuer'
import { ExpressSupport, HasEndpointOpts, ISingleEndpointOpts } from '@sphereon/ssi-express-support'
import express, { Express } from 'express'

import {
  accessTokenEndpoint,
  authorizationChallengeEndpoint,
  createCredentialOfferEndpoint,
  deleteCredentialOfferEndpoint,
  getBasePath,
  getCredentialEndpoint,
  getCredentialOfferEndpoint,
  getCredentialOfferReferenceEndpoint,
  getIssueStatusEndpoint,
  getMetadataEndpoints,
  pushedAuthorizationEndpoint,
} from './oid4vci-api-functions'

function buildVCIFromEnvironment() {
  const credentialsSupported: Record<string, CredentialConfigurationSupportedV1_0_13> = new CredentialSupportedBuilderV1_13()
    .withCredentialSigningAlgValuesSupported(process.env.credential_signing_alg_values_supported as string)
    .withCryptographicBindingMethod(process.env.cryptographic_binding_methods_supported as string)
    .withFormat(process.env.credential_supported_format as unknown as OID4VCICredentialFormat)
    .withCredentialName(process.env.credential_supported_name_1 as string)
    .withCredentialDefinition({
      type: [process.env.credential_supported_1_definition_type_1 as string, process.env.credential_supported_1_definition_type_2 as string],
      // TODO: setup credentialSubject here from env
      // credentialSubject
    })
    .withCredentialSupportedDisplay({
      name: process.env.credential_display_name as string,
      locale: process.env.credential_display_locale as string,
      logo: {
        url: process.env.credential_display_logo_url as string,
        alt_text: process.env.credential_display_logo_alt_text as string,
      },
      background_color: process.env.credential_display_background_color as string,
      text_color: process.env.credential_display_text_color as string,
    })
    .addCredentialSubjectPropertyDisplay(
      process.env.credential_subject_display_key1 as string,
      {
        name: process.env.credential_subject_display_key1_name as string,
        locale: process.env.credential_subject_display_key1_locale as string,
      } as IssuerCredentialSubjectDisplay, // fixme: This is wrong (remove the cast and see it has no matches)
    )
    .build()
  const issuerBuilder = new VcIssuerBuilder()
    .withTXCode({ length: process.env.user_pin_length as unknown as number, input_mode: process.env.user_pin_input_mode as 'numeric' | 'text' })
    .withAuthorizationServers(process.env.authorization_server as string)
    .withCredentialEndpoint(process.env.credential_endpoint as string)
    .withCredentialIssuer(process.env.credential_issuer as string)
    .withIssuerDisplay({
      name: process.env.issuer_name as string,
      locale: process.env.issuer_locale as string,
    })
    .withCredentialConfigurationsSupported(credentialsSupported)
    .withInMemoryCredentialOfferState()
    .withInMemoryCNonceState()

  if (process.env.authorization_server_client_id) {
    if (!process.env.authorization_server_redirect_uri) {
      throw Error('Authorization server redirect uri is required when client id is set')
    }
    issuerBuilder.withASClientMetadataParams({
      client_id: process.env.authorization_server_client_id,
      client_secret: process.env.authorization_server_client_secret,
      redirect_uris: [process.env.authorization_server_redirect_uri],
    })
  }

  return issuerBuilder.build()
}

export type ICreateCredentialOfferURIResponse = Omit<CreateCredentialOfferURIResult, 'session'>

export interface IGetCredentialOfferEndpointOpts extends ISingleEndpointOpts {
  baseUrl: string
}

export interface IDeleteCredentialOfferEndpointOpts extends ISingleEndpointOpts {
  baseUrl: string
}

export interface ICreateCredentialOfferEndpointOpts extends ISingleEndpointOpts {
  getOfferPath?: string
  qrCodeOpts?: QRCodeOpts
  baseUrl?: string
  credentialOfferReferenceBasePath?: string
  defaultCredentialOfferMode?: CredentialOfferMode
}

export interface IGetIssueStatusEndpointOpts extends ISingleEndpointOpts {
  baseUrl: string | URL
}

export interface IGetIssuePayloadEndpointOpts extends ISingleEndpointOpts {
  baseUrl: string | URL
}

export interface IAuthorizationChallengeEndpointOpts extends ISingleEndpointOpts {
  createAuthRequestUriEndpointPath?: string
  verifyAuthResponseEndpointPath?: string
  /**
   * Callback used for creating the authorization request uri used for the RP.
   * Added an optional state parameter so that when direct calls are used,
   * one could set the state value of the RP session to match the state value of the VCI session.
   */
  createAuthRequestUriCallback: (state?: string) => Promise<string>
  /**
   * Callback used for verifying the status of the authorization response.
   * This is checked by the issuer before issuing an authorization code.
   */
  verifyAuthResponseCallback: (correlationId: string) => Promise<boolean>
}

export interface IOID4VCIEndpointOpts {
  trustProxy?: boolean | Array<string>
  tokenEndpointOpts?: ITokenEndpointOpts
  notificationOpts?: ISingleEndpointOpts
  createCredentialOfferOpts?: ICreateCredentialOfferEndpointOpts
  deleteCredentialOfferOpts?: IDeleteCredentialOfferEndpointOpts
  getCredentialOfferOpts?: IGetCredentialOfferEndpointOpts
  getStatusOpts?: IGetIssueStatusEndpointOpts
  getIssuePayloadOpts?: IGetIssuePayloadEndpointOpts
  parOpts?: ISingleEndpointOpts
  authorizationChallengeOpts?: IAuthorizationChallengeEndpointOpts
}

export interface IOID4VCIServerOpts extends HasEndpointOpts {
  asClientOpts?: ClientMetadata
  endpointOpts?: IOID4VCIEndpointOpts
  baseUrl?: string
}

export class OID4VCIServer {
  private readonly _issuer: VcIssuer
  private authRequestsData: Map<string, AuthorizationRequest> = new Map()
  private readonly _app: Express
  private readonly _baseUrl: URL
  private readonly _expressSupport: ExpressSupport
  // private readonly _server?: http.Server
  private readonly _router: express.Router
  private readonly _asClientOpts?: ClientMetadata

  constructor(
    expressSupport: ExpressSupport,
    opts: IOID4VCIServerOpts & { issuer?: VcIssuer } /*If not supplied as argument, it will be fully configured from environment variables*/,
  ) {
    this._baseUrl = new URL(opts?.baseUrl ?? process.env.BASE_URL ?? opts?.issuer?.issuerMetadata?.credential_issuer ?? 'http://localhost')
    this._expressSupport = expressSupport
    this._app = expressSupport.express
    this._router = express.Router()
    this._issuer = opts?.issuer ? opts.issuer : buildVCIFromEnvironment()
    this._asClientOpts =
      opts.asClientOpts || this._issuer.asClientOpts ? ({ ...opts.asClientOpts, ...this._issuer.asClientOpts } as ClientMetadata) : undefined

    pushedAuthorizationEndpoint(this.router, this.issuer, this.authRequestsData)
    getMetadataEndpoints(this.router, this.issuer)
    let issuerPayloadPath: string | undefined
    if (this.isGetIssuePayloadEndpointEnabled(opts?.endpointOpts?.getIssuePayloadOpts)) {
      issuerPayloadPath = getCredentialOfferReferenceEndpoint(this.router, this.issuer, {
        ...opts?.endpointOpts?.getIssuePayloadOpts,
        baseUrl: this.baseUrl,
      })
    }

    if (opts?.endpointOpts?.createCredentialOfferOpts?.enabled !== false || process.env.CREDENTIAL_OFFER_ENDPOINT_ENABLED === 'true') {
      createCredentialOfferEndpoint(this.router, this.issuer, opts?.endpointOpts?.createCredentialOfferOpts, issuerPayloadPath)
      deleteCredentialOfferEndpoint(this.router, this.issuer, opts?.endpointOpts?.deleteCredentialOfferOpts)
    }
    getCredentialOfferEndpoint(this.router, this.issuer, opts?.endpointOpts?.getCredentialOfferOpts)
    getCredentialEndpoint(this.router, this.issuer, {
      ...opts?.endpointOpts?.tokenEndpointOpts,
      baseUrl: this.baseUrl,
      accessTokenVerificationCallback:
        opts.endpointOpts?.tokenEndpointOpts?.accessTokenVerificationCallback ??
        (this._asClientOpts
          ? oidcAccessTokenVerifyCallback({
              clientMetadata: this._asClientOpts,
              credentialIssuer: this._issuer.issuerMetadata.credential_issuer,
              authorizationServer: this._issuer.issuerMetadata.authorization_servers![0],
            })
          : undefined),
    })
    this.assertAccessTokenHandling()
    if (!this.isTokenEndpointDisabled(opts?.endpointOpts?.tokenEndpointOpts, opts?.asClientOpts)) {
      accessTokenEndpoint(this.router, this.issuer, { ...opts?.endpointOpts?.tokenEndpointOpts, baseUrl: this.baseUrl })
    }
    if (this.isStatusEndpointEnabled(opts?.endpointOpts?.getStatusOpts)) {
      getIssueStatusEndpoint(this.router, this.issuer, { ...opts?.endpointOpts?.getStatusOpts, baseUrl: this.baseUrl })
    }
    if (this.isAuthorizationChallengeEndpointEnabled(opts?.endpointOpts?.authorizationChallengeOpts)) {
      if (!opts?.endpointOpts?.authorizationChallengeOpts?.createAuthRequestUriCallback) {
        throw Error(`Unable to enable authorization challenge endpoint. No createAuthRequestUriCallback present in authorization challenge options`)
      } else if (!opts?.endpointOpts?.authorizationChallengeOpts?.verifyAuthResponseCallback) {
        throw Error(`Unable to enable authorization challenge endpoint. No verifyAuthResponseCallback present in authorization challenge options`)
      }
      authorizationChallengeEndpoint(this.router, this.issuer, { ...opts?.endpointOpts?.authorizationChallengeOpts, baseUrl: this.baseUrl })
    }
    this._app.use(getBasePath(this.baseUrl), this._router)
  }

  public get app(): Express {
    return this._app
  }

  /*public get server(): http.Server | undefined {
    return this._server
  }*/

  public get router(): express.Router {
    return this._router
  }

  get issuer(): VcIssuer {
    return this._issuer
  }

  public async stop() {
    if (!this._expressSupport) {
      throw Error('Cannot stop server is the REST API is only a router of an existing express app')
    }
    await this._expressSupport.stop()
  }

  private isTokenEndpointDisabled(tokenEndpointOpts?: ITokenEndpointOpts, asClientMetadata?: ClientMetadata) {
    return tokenEndpointOpts?.tokenEndpointDisabled === true || process.env.TOKEN_ENDPOINT_DISABLED === 'true' || asClientMetadata
  }

  private isStatusEndpointEnabled(statusEndpointOpts?: IGetIssueStatusEndpointOpts) {
    return statusEndpointOpts?.enabled !== false || process.env.STATUS_ENDPOINT_ENABLED !== 'false'
  }

  private isGetIssuePayloadEndpointEnabled(payloadEndpointOpts?: IGetIssuePayloadEndpointOpts) {
    return payloadEndpointOpts?.enabled !== false || process.env.STATUS_ENDPOINT_ENABLED !== 'false'
  }

  private isAuthorizationChallengeEndpointEnabled(authorizationChallengeEndpointOpts?: IAuthorizationChallengeEndpointOpts) {
    return authorizationChallengeEndpointOpts?.enabled === true || process.env.AUTHORIZATION_CHALLENGE_ENDPOINT_ENABLED === 'true'
  }

  private assertAccessTokenHandling(tokenEndpointOpts?: ITokenEndpointOpts) {
    const authServer = this.issuer.issuerMetadata.authorization_servers
    if (this.isTokenEndpointDisabled(tokenEndpointOpts, this.issuer.asClientOpts)) {
      if (!authServer || authServer.length === 0) {
        throw Error(
          `No Authorization Server (AS) is defined in the issuer metadata and the token endpoint is disabled. An AS or token endpoints needs to be present`,
        )
      }
      if (this.issuer.asClientOpts) {
        console.log(`Token endpoint disabled because AS client metadata is set for ${authServer[0]}`)
      } else {
        console.log(`Token endpoint disabled by configuration`)
      }
    } else {
      if (authServer && authServer.some((as) => as !== this.issuer.issuerMetadata.credential_issuer)) {
        throw Error(
          `An external Authorization Server (AS) was already enabled in the issuer metadata (${authServer}). Cannot both have an AS and enable the token endpoint at the same time `,
        )
      } else if (this._asClientOpts) {
        throw Error(`OIDC Client metadata is set, but the token endpoint is not disabled. This is not supported.`)
      }
    }
  }
  get baseUrl(): URL {
    return this._baseUrl
  }
}
