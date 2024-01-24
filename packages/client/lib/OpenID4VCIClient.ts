import {
  AccessTokenResponse,
  Alg,
  AuthorizationRequestOpts,
  AuthzFlowType,
  CodeChallengeMethod,
  CredentialOfferPayloadV1_0_08,
  CredentialOfferRequestWithBaseUrl,
  CredentialResponse,
  CredentialSupported,
  EndpointMetadataResult,
  getClientIdFromCredentialOfferPayload,
  getIssuerFromCredentialOfferPayload,
  getSupportedCredentials,
  getTypesFromCredentialSupported,
  JWK,
  KID_JWK_X5C_ERROR,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  PKCEOpts,
  ProofOfPossessionCallbacks,
} from '@sphereon/oid4vci-common';
import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { AccessTokenClient } from './AccessTokenClient';
import { createAuthorizationRequestUrl } from './AuthorizationCodeClient';
import { CredentialOfferClient } from './CredentialOfferClient';
import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { MetadataClient } from './MetadataClient';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import { generateMissingPKCEOpts } from './functions/AuthorizationUtil';

const debug = Debug('sphereon:oid4vci');

export class OpenID4VCIClient {
  private readonly _credentialOffer?: CredentialOfferRequestWithBaseUrl;
  private readonly _credentialIssuer: string;
  private _clientId?: string;
  private _kid: string | undefined;
  private _jwk: JWK | undefined;
  private _alg: Alg | string | undefined;
  private _endpointMetadata: EndpointMetadataResult | undefined;
  private _accessTokenResponse: AccessTokenResponse | undefined;
  private _pkce: PKCEOpts = { disabled: false, codeChallengeMethod: CodeChallengeMethod.S256 };
  private _authorizationRequestOpts?: AuthorizationRequestOpts;

  private _authorizationURL?: string;

  private constructor({
    credentialOffer,
    clientId,
    kid,
    alg,
    credentialIssuer,
    pkce,
    authorizationRequest,
  }: {
    credentialOffer?: CredentialOfferRequestWithBaseUrl;
    kid?: string;
    alg?: Alg | string;
    clientId?: string;
    credentialIssuer?: string;
    pkce?: PKCEOpts;
    authorizationRequest?: AuthorizationRequestOpts; // Can be provided here, or when manually calling createAuthorizationUrl
  }) {
    this._credentialOffer = credentialOffer;
    const issuer = credentialIssuer ?? (credentialOffer ? getIssuerFromCredentialOfferPayload(credentialOffer.credential_offer) : undefined);
    if (!issuer) {
      throw Error('No credential issuer supplied or deduced from offer');
    }
    this._credentialIssuer = issuer;
    this._kid = kid;
    this._alg = alg;
    this._clientId = clientId ?? (credentialOffer ? getClientIdFromCredentialOfferPayload(credentialOffer.credential_offer) : undefined);
    this._pkce = { ...this._pkce, ...pkce };
    this._authorizationRequestOpts = this.syncAuthorizationRequestOpts(authorizationRequest);
  }

  public static async fromCredentialIssuer({
    kid,
    alg,
    retrieveServerMetadata,
    clientId,
    credentialIssuer,
    pkce,
    authorizationRequest,
    createAuthorizationRequestURL,
  }: {
    credentialIssuer: string;
    kid?: string;
    alg?: Alg | string;
    retrieveServerMetadata?: boolean;
    clientId?: string;
    createAuthorizationRequestURL?: boolean;
    authorizationRequest?: AuthorizationRequestOpts; // Can be provided here, or when manually calling createAuthorizationUrl
    pkce?: PKCEOpts;
  }) {
    const client = new OpenID4VCIClient({
      kid,
      alg,
      clientId: clientId ?? authorizationRequest?.clientId,
      credentialIssuer,
      pkce,
      authorizationRequest,
    });
    if (retrieveServerMetadata === undefined || retrieveServerMetadata) {
      await client.retrieveServerMetadata();
    }
    if (createAuthorizationRequestURL === undefined || createAuthorizationRequestURL) {
      await client.createAuthorizationRequestUrl({ authorizationRequest, pkce });
    }
    return client;
  }

  public static async fromURI({
    uri,
    kid,
    alg,
    retrieveServerMetadata,
    clientId,
    pkce,
    createAuthorizationRequestURL,
    authorizationRequest,
    resolveOfferUri,
  }: {
    uri: string;
    kid?: string;
    alg?: Alg | string;
    retrieveServerMetadata?: boolean;
    createAuthorizationRequestURL?: boolean;
    resolveOfferUri?: boolean;
    pkce?: PKCEOpts;
    clientId?: string;
    authorizationRequest?: AuthorizationRequestOpts; // Can be provided here, or when manually calling createAuthorizationUrl
  }): Promise<OpenID4VCIClient> {
    const credentialOfferClient = await CredentialOfferClient.fromURI(uri, { resolve: resolveOfferUri });
    const client = new OpenID4VCIClient({
      credentialOffer: credentialOfferClient,
      kid,
      alg,
      clientId: clientId ?? authorizationRequest?.clientId ?? credentialOfferClient.clientId,
      pkce,
      authorizationRequest,
    });

    if (retrieveServerMetadata === undefined || retrieveServerMetadata) {
      await client.retrieveServerMetadata();
    }
    if (
      credentialOfferClient.supportedFlows.includes(AuthzFlowType.AUTHORIZATION_CODE_FLOW) &&
      (createAuthorizationRequestURL === undefined || createAuthorizationRequestURL)
    ) {
      console.log(`AUTH REQ`);
      await client.createAuthorizationRequestUrl({ authorizationRequest, pkce });
      console.log(`AUTH REQ URL: ${client._authorizationURL}`);
    }

    return client;
  }

  public async createAuthorizationRequestUrl(opts?: { authorizationRequest?: AuthorizationRequestOpts; pkce?: PKCEOpts }): Promise<string> {
    if (!this._authorizationURL) {
      this.calculatePKCEOpts(opts?.pkce);
      this._authorizationRequestOpts = this.syncAuthorizationRequestOpts(opts?.authorizationRequest);
      if (!this._authorizationRequestOpts) {
        throw Error(`No Authorization Request options present or provided in this call`);
      }

      // todo: Probably can go with current logic in MetadataClient who will always set the authorization_endpoint when found
      //  handling this because of the support for v1_0-08
      if (
        this._endpointMetadata?.credentialIssuerMetadata &&
        'authorization_endpoint' in this._endpointMetadata.credentialIssuerMetadata
      ) {
        this._endpointMetadata.authorization_endpoint = this._endpointMetadata.credentialIssuerMetadata.authorization_endpoint as string;
      }
      this._authorizationURL = await createAuthorizationRequestUrl({
        pkce: this._pkce,
        endpointMetadata: this.endpointMetadata,
        authorizationRequest: this._authorizationRequestOpts,
        credentialOffer: this.credentialOffer,
        credentialsSupported: this.getCredentialsSupported(true),
      });
    }
    return this._authorizationURL;
  }

  public async retrieveServerMetadata(): Promise<EndpointMetadataResult> {
    this.assertIssuerData();
    if (!this._endpointMetadata) {
      if (this.credentialOffer) {
        this._endpointMetadata = await MetadataClient.retrieveAllMetadataFromCredentialOffer(this.credentialOffer);
      } else if (this._credentialIssuer) {
        this._endpointMetadata = await MetadataClient.retrieveAllMetadata(this._credentialIssuer);
      } else {
        throw Error(`Cannot retrieve issuer metadata without either a credential offer, or issuer value`);
      }
    }
    return this.endpointMetadata;
  }

  private calculatePKCEOpts(pkce?: PKCEOpts) {
    this._pkce = generateMissingPKCEOpts({ ...this._pkce, ...pkce });
  }

  public async acquireAccessToken(opts?: {
    pin?: string;
    clientId?: string;
    codeVerifier?: string;
    code?: string;
    redirectUri?: string;
  }): Promise<AccessTokenResponse> {
    const { pin, clientId, code, redirectUri } = opts ?? {};

    if (opts?.codeVerifier) {
      this._pkce.codeVerifier = opts.codeVerifier;
    }
    this.assertIssuerData();

    if (clientId) {
      this._clientId = clientId;
    }
    if (!this._accessTokenResponse) {
      const accessTokenClient = new AccessTokenClient();

      const response = await accessTokenClient.acquireAccessToken({
        credentialOffer: this.credentialOffer,
        metadata: this.endpointMetadata,
        credentialIssuer: this.getIssuer(),
        pin,
        ...(!this._pkce.disabled && { codeVerifier: this._pkce.codeVerifier }),
        code,
        redirectUri,
        asOpts: { clientId },
      });

      if (response.errorBody) {
        debug(`Access token error:\r\n${response.errorBody}`);
        throw Error(
          `Retrieving an access token from ${this._endpointMetadata?.token_endpoint} for issuer ${this.getIssuer()} failed with status: ${
            response.origResponse.status
          }`,
        );
      } else if (!response.successBody) {
        debug(`Access token error. No success body`);
        throw Error(
          `Retrieving an access token from ${this._endpointMetadata
            ?.token_endpoint} for issuer ${this.getIssuer()} failed as there was no success response body`,
        );
      }
      this._accessTokenResponse = response.successBody;
    }

    return this.accessTokenResponse;
  }

  public async acquireCredentials({
    credentialTypes,
    proofCallbacks,
    format,
    kid,
    jwk,
    alg,
    jti,
    deferredCredentialAwait,
    deferredCredentialIntervalInMS,
  }: {
    credentialTypes: string | string[];
    proofCallbacks: ProofOfPossessionCallbacks<any>;
    format?: CredentialFormat | OID4VCICredentialFormat;
    kid?: string;
    jwk?: JWK;
    alg?: Alg | string;
    jti?: string;
    deferredCredentialAwait?: boolean;
    deferredCredentialIntervalInMS?: number;
  }): Promise<CredentialResponse> {
    if ([jwk, kid].filter((v) => v !== undefined).length > 1) {
      throw new Error(KID_JWK_X5C_ERROR + `. jwk: ${jwk !== undefined}, kid: ${kid !== undefined}`);
    }

    if (alg) this._alg = alg;
    if (jwk) this._jwk = jwk;
    if (kid) this._kid = kid;

    const requestBuilder = this.credentialOffer
      ? CredentialRequestClientBuilder.fromCredentialOffer({
          credentialOffer: this.credentialOffer,
          metadata: this.endpointMetadata,
        })
      : CredentialRequestClientBuilder.fromCredentialIssuer({
          credentialIssuer: this.getIssuer(),
          credentialTypes,
          metadata: this.endpointMetadata,
          version: this.version(),
        });

    requestBuilder.withTokenFromResponse(this.accessTokenResponse);
    requestBuilder.withDeferredCredentialAwait(deferredCredentialAwait ?? false, deferredCredentialIntervalInMS);
    if (this.endpointMetadata?.credentialIssuerMetadata) {
      const metadata = this.endpointMetadata.credentialIssuerMetadata;
      const types = Array.isArray(credentialTypes) ? [...credentialTypes].sort() : [credentialTypes];

      if (metadata.credentials_supported && Array.isArray(metadata.credentials_supported)) {
        let typeSupported = false;

        metadata.credentials_supported.forEach((supportedCredential) => {
          const subTypes = getTypesFromCredentialSupported(supportedCredential);
          if (
            subTypes.sort().every((t, i) => types[i] === t) ||
            (types.length === 1 && (types[0] === supportedCredential.id || subTypes.includes(types[0])))
          ) {
            typeSupported = true;
          }
        });

        if (!typeSupported) {
          console.log(`Not all credential types ${JSON.stringify(credentialTypes)} are present in metadata for ${this.getIssuer()}`);
          // throw Error(`Not all credential types ${JSON.stringify(credentialTypes)} are supported by issuer ${this.getIssuer()}`);
        }
      } else if (metadata.credentials_supported && !Array.isArray(metadata.credentials_supported)) {
        const credentialsSupported = metadata.credentials_supported;
        if (types.some((type) => !metadata.credentials_supported || !credentialsSupported[type])) {
          throw Error(`Not all credential types ${JSON.stringify(credentialTypes)} are supported by issuer ${this.getIssuer()}`);
        }
      }
      // todo: Format check? We might end up with some disjoint type / format combinations supported by the server
    }
    const credentialRequestClient = requestBuilder.build();
    const proofBuilder = ProofOfPossessionBuilder.fromAccessTokenResponse({
      accessTokenResponse: this.accessTokenResponse,
      callbacks: proofCallbacks,
      version: this.version(),
    })
      .withIssuer(this.getIssuer())
      .withAlg(this.alg);

    if (this._jwk) {
      proofBuilder.withJWK(this._jwk);
    }
    if (this._kid) {
      proofBuilder.withKid(this._kid);
    }

    if (this.clientId) {
      proofBuilder.withClientId(this.clientId);
    }
    if (jti) {
      proofBuilder.withJti(jti);
    }
    const response = await credentialRequestClient.acquireCredentialsUsingProof({
      proofInput: proofBuilder,
      credentialTypes: credentialTypes,
      format,
    });
    if (response.errorBody) {
      debug(`Credential request error:\r\n${JSON.stringify(response.errorBody)}`);
      throw Error(
        `Retrieving a credential from ${this._endpointMetadata?.credential_endpoint} for issuer ${this.getIssuer()} failed with status: ${
          response.origResponse.status
        }`,
      );
    } else if (!response.successBody) {
      debug(`Credential request error. No success body`);
      throw Error(
        `Retrieving a credential from ${this._endpointMetadata
          ?.credential_endpoint} for issuer ${this.getIssuer()} failed as there was no success response body`,
      );
    }
    return response.successBody;
  }

  // FIXME: We really should convert <v11 to v12 objects first. Right now the logic doesn't map nicely and is brittle.
  // We should resolve IDs to objects first in case of strings.
  // When < v11 convert into a v12 object. When v12 object retain it.
  // Then match the object array on server metadata
  getCredentialsSupported(
    restrictToInitiationTypes: boolean,
    format?: (OID4VCICredentialFormat | string) | (OID4VCICredentialFormat | string)[],
  ): CredentialSupported[] {
    return getSupportedCredentials({
      issuerMetadata: this.endpointMetadata.credentialIssuerMetadata,
      version: this.version(),
      format: format,
      types: restrictToInitiationTypes ? this.getCredentialOfferTypes() : undefined,
    });
  }

  getCredentialOfferTypes(): string[][] {
    if (!this.credentialOffer) {
      return [];
    } else if (this.credentialOffer.version < OpenId4VCIVersion.VER_1_0_11) {
      const orig = this.credentialOffer.original_credential_offer as CredentialOfferPayloadV1_0_08;
      const types: string[] = typeof orig.credential_type === 'string' ? [orig.credential_type] : orig.credential_type;
      const result: string[][] = [];
      result[0] = types;
      return result;
    } else {
      return this.credentialOffer.credential_offer.credentials.map((c) => {
        if (typeof c === 'string') {
          return [c];
        } else if ('types' in c) {
          return c.types;
        } else if ('vct' in c) {
          return [c.vct];
        } else {
          return c.credential_definition.types;
        }
      });
    }
  }

  issuerSupportedFlowTypes(): AuthzFlowType[] {
    return (
      this.credentialOffer?.supportedFlows ??
      (this._endpointMetadata?.credentialIssuerMetadata?.authorization_endpoint ? [AuthzFlowType.AUTHORIZATION_CODE_FLOW] : [])
    );
  }

  isFlowTypeSupported(flowType: AuthzFlowType): boolean {
    return this.issuerSupportedFlowTypes().includes(flowType);
  }

  get authorizationURL(): string | undefined {
    return this._authorizationURL;
  }

  public hasAuthorizationURL(): boolean {
    return !!this.authorizationURL;
  }

  get credentialOffer(): CredentialOfferRequestWithBaseUrl | undefined {
    return this._credentialOffer;
  }

  public version(): OpenId4VCIVersion {
    return this.credentialOffer?.version ?? OpenId4VCIVersion.VER_1_0_11;
  }

  public get endpointMetadata(): EndpointMetadataResult {
    this.assertServerMetadata();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return this._endpointMetadata!;
  }

  get kid(): string {
    this.assertIssuerData();
    if (!this._kid) {
      throw new Error('No value for kid is supplied');
    }
    return this._kid;
  }

  get alg(): string {
    this.assertIssuerData();
    if (!this._alg) {
      throw new Error('No value for alg is supplied');
    }
    return this._alg;
  }

  get clientId(): string | undefined {
    return this._clientId;
  }

  get accessTokenResponse(): AccessTokenResponse {
    this.assertAccessToken();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return this._accessTokenResponse!;
  }

  public getIssuer(): string {
    this.assertIssuerData();
    return this._credentialIssuer!;
  }

  public getAccessTokenEndpoint(): string {
    this.assertIssuerData();
    return this.endpointMetadata
      ? this.endpointMetadata.token_endpoint
      : AccessTokenClient.determineTokenURL({ issuerOpts: { issuer: this.getIssuer() } });
  }

  public getCredentialEndpoint(): string {
    this.assertIssuerData();
    return this.endpointMetadata ? this.endpointMetadata.credential_endpoint : `${this.getIssuer()}/credential`;
  }

  public hasDeferredCredentialEndpoint(): boolean {
    return !!this.getAccessTokenEndpoint();
  }

  public getDeferredCredentialEndpoint(): string {
    this.assertIssuerData();
    return this.endpointMetadata ? this.endpointMetadata.credential_endpoint : `${this.getIssuer()}/credential`;
  }

  private assertIssuerData(): void {
    if (!this._credentialIssuer) {
      throw Error(`No credential issuer value present`);
    } else if (!this._credentialOffer && this._endpointMetadata && this.issuerSupportedFlowTypes().length === 0) {
      throw Error(`No issuance initiation or credential offer present`);
    }
  }

  private assertServerMetadata(): void {
    if (!this._endpointMetadata) {
      throw Error('No server metadata');
    }
  }

  private assertAccessToken(): void {
    if (!this._accessTokenResponse) {
      throw Error(`No access token present`);
    }
  }

  private syncAuthorizationRequestOpts(opts?: AuthorizationRequestOpts): AuthorizationRequestOpts {
    let authorizationRequestOpts = { ...this._authorizationRequestOpts, ...opts } as AuthorizationRequestOpts;
    if (!authorizationRequestOpts) {
      authorizationRequestOpts = { redirectUri: 'openid4vc%3A' }
    }
    const clientId = authorizationRequestOpts.clientId ?? this._clientId
    this._clientId = clientId;
    authorizationRequestOpts.clientId = clientId;

    if (!authorizationRequestOpts.redirectUri) {
      authorizationRequestOpts.redirectUri = 'openid4vc%3A';
    }
    return authorizationRequestOpts;
  }
}
