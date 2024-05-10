import * as console from 'console'
import process from 'process'

import {
  AuthorizationRequest,
  CredentialConfigurationSupported,
  IssuerCredentialSubjectDisplay,
  OID4VCICredentialFormat,
  QRCodeOpts,
  TxCode,
} from '@sphereon/oid4vci-common'
import { CredentialSupportedBuilderV1_13, ITokenEndpointOpts, VcIssuer, VcIssuerBuilder } from '@sphereon/oid4vci-issuer'
import { ExpressSupport, HasEndpointOpts, ISingleEndpointOpts } from '@sphereon/ssi-express-support'
import express, { Express } from 'express'

import {
  accessTokenEndpoint,
  createCredentialOfferEndpoint,
  getBasePath,
  getCredentialEndpoint,
  getCredentialOfferEndpoint,
  getIssueStatusEndpoint,
  getMetadataEndpoint,
  pushedAuthorizationEndpoint,
} from './oid4vci-api-functions'

function buildVCIFromEnvironment<DIDDoc extends object>() {
  const credentialsSupported: Record<string, CredentialConfigurationSupported> = new CredentialSupportedBuilderV1_13()
    .withCryptographicSuitesSupported(process.env.cryptographic_suites_supported as string)
    .withCryptographicBindingMethod(process.env.cryptographic_binding_methods_supported as string)
    .withFormat(process.env.credential_supported_format as unknown as OID4VCICredentialFormat)
    .withId(process.env.credential_supported_id as string)
    .withTypes([process.env.credential_supported_types_1 as string, process.env.credential_supported_types_2 as string])
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
  return new VcIssuerBuilder<DIDDoc>()
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
    .build()
}

export type ICreateCredentialOfferURIResponse = {
  uri: string
  userPin?: string
  tsCode?: TxCode
}

export interface IGetCredentialOfferEndpointOpts extends ISingleEndpointOpts {
  baseUrl: string
}

export interface ICreateCredentialOfferEndpointOpts extends ISingleEndpointOpts {
  getOfferPath?: string
  qrCodeOpts?: QRCodeOpts
}

export interface IGetIssueStatusEndpointOpts extends ISingleEndpointOpts {
  baseUrl: string | URL
}

export interface IOID4VCIServerOpts extends HasEndpointOpts {
  endpointOpts?: {
    tokenEndpointOpts?: ITokenEndpointOpts
    createCredentialOfferOpts?: ICreateCredentialOfferEndpointOpts
    getCredentialOfferOpts?: IGetCredentialOfferEndpointOpts
    getStatusOpts?: IGetIssueStatusEndpointOpts
    parOpts?: ISingleEndpointOpts
  }
  baseUrl?: string
}

export class OID4VCIServer<DIDDoc extends object> {
  private readonly _issuer: VcIssuer<DIDDoc>
  private authRequestsData: Map<string, AuthorizationRequest> = new Map()
  private readonly _app: Express
  private readonly _baseUrl: URL
  private readonly _expressSupport: ExpressSupport
  // private readonly _server?: http.Server
  private readonly _router: express.Router

  constructor(
    expressSupport: ExpressSupport,
    opts: IOID4VCIServerOpts & { issuer?: VcIssuer<DIDDoc> } /*If not supplied as argument, it will be fully configured from environment variables*/,
  ) {
    this._baseUrl = new URL(opts?.baseUrl ?? process.env.BASE_URL ?? opts?.issuer?.issuerMetadata?.credential_issuer ?? 'http://localhost')
    this._expressSupport = expressSupport
    this._app = expressSupport.express
    this._router = express.Router()
    this._issuer = opts?.issuer ? opts.issuer : buildVCIFromEnvironment()

    pushedAuthorizationEndpoint(this.router, this.issuer, this.authRequestsData)
    getMetadataEndpoint(this.router, this.issuer)
    if (opts?.endpointOpts?.createCredentialOfferOpts?.enabled !== false || process.env.CREDENTIAL_OFFER_ENDPOINT_EBALBED === 'true') {
      createCredentialOfferEndpoint(this.router, this.issuer, opts?.endpointOpts?.createCredentialOfferOpts)
    }
    getCredentialOfferEndpoint(this.router, this.issuer, opts?.endpointOpts?.getCredentialOfferOpts)
    getCredentialEndpoint(this.router, this.issuer, { ...opts?.endpointOpts?.tokenEndpointOpts, baseUrl: this.baseUrl })
    this.assertAccessTokenHandling()
    if (!this.isTokenEndpointDisabled(opts?.endpointOpts?.tokenEndpointOpts)) {
      accessTokenEndpoint(this.router, this.issuer, { ...opts?.endpointOpts?.tokenEndpointOpts, baseUrl: this.baseUrl })
    }
    if (this.isStatusEndpointEnabled(opts?.endpointOpts?.getStatusOpts)) {
      getIssueStatusEndpoint(this.router, this.issuer, { ...opts?.endpointOpts?.getStatusOpts, baseUrl: this.baseUrl })
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

  get issuer(): VcIssuer<DIDDoc> {
    return this._issuer
  }

  public async stop() {
    if (!this._expressSupport) {
      throw Error('Cannot stop server is the REST API is only a router of an existing express app')
    }
    await this._expressSupport.stop()
  }

  private isTokenEndpointDisabled(tokenEndpointOpts?: ITokenEndpointOpts) {
    return tokenEndpointOpts?.tokenEndpointDisabled === true || process.env.TOKEN_ENDPOINT_DISABLED === 'true'
  }

  private isStatusEndpointEnabled(statusEndpointOpts?: IGetIssueStatusEndpointOpts) {
    return statusEndpointOpts?.enabled !== false || process.env.STATUS_ENDPOINT_ENABLED === 'false'
  }

  private assertAccessTokenHandling(tokenEndpointOpts?: ITokenEndpointOpts) {
    const authServer = this.issuer.issuerMetadata.authorization_servers
    if (this.isTokenEndpointDisabled(tokenEndpointOpts)) {
      if (!authServer) {
        throw Error(
          `No Authorization Server (AS) is defined in the issuer metadata and the token endpoint is disabled. An AS or token endpoints needs to be present`,
        )
      }
      console.log('Token endpoint disabled by configuration')
    } else {
      if (authServer) {
        throw Error(
          `A Authorization Server (AS) was already enabled in the issuer metadata (${authServer}). Cannot both have an AS and enable the token endpoint at the same time `,
        )
      }
    }
  }
  get baseUrl(): URL {
    return this._baseUrl
  }
}
