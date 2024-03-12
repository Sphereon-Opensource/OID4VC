import {
  AccessTokenResponse,
  Alg,
  AuthorizationRequestOpts,
  AuthorizationResponse,
  AuthzFlowType,
  CodeChallengeMethod,
  CredentialOfferPayloadV1_0_08,
  CredentialOfferRequestWithBaseUrl,
  CredentialResponse,
  CredentialSupported,
  DefaultURISchemes,
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
  toAuthorizationResponsePayload,
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

export interface OpenID4VCIClientState {
  credentialIssuer: string;
  credentialOffer?: CredentialOfferRequestWithBaseUrl;
  clientId?: string;
  kid?: string;
  jwk?: JWK;
  alg?: Alg | string;
  endpointMetadata?: EndpointMetadataResult;
  accessTokenResponse?: AccessTokenResponse;
  authorizationRequestOpts?: AuthorizationRequestOpts;
  authorizationCodeResponse?: AuthorizationResponse;
  pkce: PKCEOpts;
  authorizationURL?: string;
}

export class OpenID4VCIClient {
  private readonly _state: OpenID4VCIClientState;

  private constructor({
    credentialOffer,
    clientId,
    kid,
    alg,
    credentialIssuer,
    pkce,
    authorizationRequest,
    jwk,
    endpointMetadata,
    accessTokenResponse,
    authorizationRequestOpts,
    authorizationCodeResponse,
    authorizationURL,
  }: {
    credentialOffer?: CredentialOfferRequestWithBaseUrl;
    kid?: string;
    alg?: Alg | string;
    clientId?: string;
    credentialIssuer?: string;
    pkce?: PKCEOpts;
    authorizationRequest?: AuthorizationRequestOpts; // Can be provided here, or when manually calling createAuthorizationUrl
    jwk?: JWK;
    endpointMetadata?: EndpointMetadataResult;
    accessTokenResponse?: AccessTokenResponse;
    authorizationRequestOpts?: AuthorizationRequestOpts;
    authorizationCodeResponse?: AuthorizationResponse;
    authorizationURL?: string;
  }) {
    const issuer = credentialIssuer ?? (credentialOffer ? getIssuerFromCredentialOfferPayload(credentialOffer.credential_offer) : undefined);
    if (!issuer) {
      throw Error('No credential issuer supplied or deduced from offer');
    }
    this._state = {
      credentialOffer,
      credentialIssuer: issuer,
      kid,
      alg,
      // TODO: We need to refactor this and always explicitly call createAuthorizationRequestUrl, so we can have a credential selection first and use the kid as a default for the client id
      clientId: clientId ?? (credentialOffer && getClientIdFromCredentialOfferPayload(credentialOffer.credential_offer)) ?? kid?.split('#')[0],
      pkce: { disabled: false, codeChallengeMethod: CodeChallengeMethod.S256, ...pkce },
      authorizationRequestOpts,
      authorizationCodeResponse,
      jwk,
      endpointMetadata,
      accessTokenResponse,
      authorizationURL,
    };
    // Running syncAuthorizationRequestOpts later as it is using the state
    if (!this._state.authorizationRequestOpts) {
      this._state.authorizationRequestOpts = this.syncAuthorizationRequestOpts(authorizationRequest);
    }
    debug(`Authorization req options: ${JSON.stringify(this._state.authorizationRequestOpts, null, 2)}`);
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

  public static async fromState({ state }: { state: OpenID4VCIClientState | string }): Promise<OpenID4VCIClient> {
    const clientState = typeof state === 'string' ? JSON.parse(state) : state;

    return new OpenID4VCIClient(clientState);
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
      await client.createAuthorizationRequestUrl({ authorizationRequest, pkce });
      debug(`Authorization Request URL: ${client._state.authorizationURL}`);
    }

    return client;
  }

  /**
   * Allows you to create an Authorization Request URL when using an Authorization Code flow. This URL needs to be accessed using the front channel (browser)
   *
   * The Identity provider would present a login screen typically; after you authenticated, it would redirect to the provided redirectUri; which can be same device or cross-device
   * @param opts
   */
  public async createAuthorizationRequestUrl(opts?: { authorizationRequest?: AuthorizationRequestOpts; pkce?: PKCEOpts }): Promise<string> {
    if (!this._state.authorizationURL) {
      this.calculatePKCEOpts(opts?.pkce);
      this._state.authorizationRequestOpts = this.syncAuthorizationRequestOpts(opts?.authorizationRequest);
      if (!this._state.authorizationRequestOpts) {
        throw Error(`No Authorization Request options present or provided in this call`);
      }

      // todo: Probably can go with current logic in MetadataClient who will always set the authorization_endpoint when found
      //  handling this because of the support for v1_0-08
      if (
        this._state.endpointMetadata?.credentialIssuerMetadata &&
        'authorization_endpoint' in this._state.endpointMetadata.credentialIssuerMetadata
      ) {
        this._state.endpointMetadata.authorization_endpoint = this._state.endpointMetadata.credentialIssuerMetadata.authorization_endpoint as string;
      }
      this._state.authorizationURL = await createAuthorizationRequestUrl({
        pkce: this._state.pkce,
        endpointMetadata: this.endpointMetadata,
        authorizationRequest: this._state.authorizationRequestOpts,
        credentialOffer: this.credentialOffer,
        credentialsSupported: this.getCredentialsSupported(true),
      });
    }
    return this._state.authorizationURL;
  }

  public async retrieveServerMetadata(): Promise<EndpointMetadataResult> {
    this.assertIssuerData();
    if (!this._state.endpointMetadata) {
      if (this.credentialOffer) {
        this._state.endpointMetadata = await MetadataClient.retrieveAllMetadataFromCredentialOffer(this.credentialOffer);
      } else if (this._state.credentialIssuer) {
        this._state.endpointMetadata = await MetadataClient.retrieveAllMetadata(this._state.credentialIssuer);
      } else {
        throw Error(`Cannot retrieve issuer metadata without either a credential offer, or issuer value`);
      }
    }

    return this.endpointMetadata;
  }

  private calculatePKCEOpts(pkce?: PKCEOpts) {
    this._state.pkce = generateMissingPKCEOpts({ ...this._state.pkce, ...pkce });
  }

  public async acquireAccessToken(opts?: {
    pin?: string;
    clientId?: string;
    codeVerifier?: string;
    authorizationResponse?: string | AuthorizationResponse; // Pass in an auth response, either as URI/redirect, or object
    code?: string; // Directly pass in a code from an auth response
    redirectUri?: string;
  }): Promise<AccessTokenResponse> {
    const { pin, clientId } = opts ?? {};
    let { redirectUri } = opts ?? {};
    if (opts?.authorizationResponse) {
      this._state.authorizationCodeResponse = { ...toAuthorizationResponsePayload(opts.authorizationResponse) };
    } else if (opts?.code) {
      this._state.authorizationCodeResponse = { code: opts.code };
    }
    const code = this._state.authorizationCodeResponse?.code;

    if (opts?.codeVerifier) {
      this._state.pkce.codeVerifier = opts.codeVerifier;
    }
    this.assertIssuerData();

    if (clientId) {
      this._state.clientId = clientId;
    }
    if (!this._state.accessTokenResponse) {
      const accessTokenClient = new AccessTokenClient();

      if (redirectUri && redirectUri !== this._state.authorizationRequestOpts?.redirectUri) {
        console.log(
          `Redirect URI mismatch between access-token (${redirectUri}) and authorization request (${this._state.authorizationRequestOpts?.redirectUri}). According to the specification that is not allowed.`,
        );
      }
      if (this._state.authorizationRequestOpts?.redirectUri && !redirectUri) {
        redirectUri = this._state.authorizationRequestOpts.redirectUri;
      }

      const response = await accessTokenClient.acquireAccessToken({
        credentialOffer: this.credentialOffer,
        metadata: this.endpointMetadata,
        credentialIssuer: this.getIssuer(),
        pin,
        ...(!this._state.pkce.disabled && { codeVerifier: this._state.pkce.codeVerifier }),
        code,
        redirectUri,
        asOpts: { clientId: this.clientId },
      });

      if (response.errorBody) {
        debug(`Access token error:\r\n${JSON.stringify(response.errorBody)}`);
        throw Error(
          `Retrieving an access token from ${this._state.endpointMetadata?.token_endpoint} for issuer ${this.getIssuer()} failed with status: ${
            response.origResponse.status
          }`,
        );
      } else if (!response.successBody) {
        debug(`Access token error. No success body`);
        throw Error(
          `Retrieving an access token from ${this._state.endpointMetadata
            ?.token_endpoint} for issuer ${this.getIssuer()} failed as there was no success response body`,
        );
      }
      this._state.accessTokenResponse = response.successBody;
    }

    return this.accessTokenResponse;
  }

  public async acquireCredentials({
    credentialTypes,
    context,
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
    context?: string[];
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

    if (alg) this._state.alg = alg;
    if (jwk) this._state.jwk = jwk;
    if (kid) this._state.kid = kid;

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
      const types = Array.isArray(credentialTypes) ? credentialTypes : [credentialTypes];

      if (metadata.credentials_supported && Array.isArray(metadata.credentials_supported)) {
        let typeSupported = false;

        metadata.credentials_supported.forEach((supportedCredential) => {
          const subTypes = getTypesFromCredentialSupported(supportedCredential);
          if (
            subTypes.every((t, i) => types[i] === t) ||
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

    if (this._state.jwk) {
      proofBuilder.withJWK(this._state.jwk);
    }
    if (this._state.kid) {
      proofBuilder.withKid(this._state.kid);
    }

    if (this.clientId) {
      proofBuilder.withClientId(this.clientId);
    }
    if (jti) {
      proofBuilder.withJti(jti);
    }
    const response = await credentialRequestClient.acquireCredentialsUsingProof({
      proofInput: proofBuilder,
      credentialTypes,
      context,
      format,
    });
    if (response.errorBody) {
      debug(`Credential request error:\r\n${JSON.stringify(response.errorBody)}`);
      throw Error(
        `Retrieving a credential from ${this._state.endpointMetadata?.credential_endpoint} for issuer ${this.getIssuer()} failed with status: ${
          response.origResponse.status
        }`,
      );
    } else if (!response.successBody) {
      debug(`Credential request error. No success body`);
      throw Error(
        `Retrieving a credential from ${this._state.endpointMetadata
          ?.credential_endpoint} for issuer ${this.getIssuer()} failed as there was no success response body`,
      );
    }
    return response.successBody;
  }

  public async exportState(): Promise<string> {
    return JSON.stringify(this._state);
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
      (this._state.endpointMetadata?.credentialIssuerMetadata?.authorization_endpoint ? [AuthzFlowType.AUTHORIZATION_CODE_FLOW] : [])
    );
  }

  isFlowTypeSupported(flowType: AuthzFlowType): boolean {
    return this.issuerSupportedFlowTypes().includes(flowType);
  }

  get authorizationURL(): string | undefined {
    return this._state.authorizationURL;
  }

  public hasAuthorizationURL(): boolean {
    return !!this.authorizationURL;
  }

  get credentialOffer(): CredentialOfferRequestWithBaseUrl | undefined {
    return this._state.credentialOffer;
  }

  public version(): OpenId4VCIVersion {
    return this.credentialOffer?.version ?? OpenId4VCIVersion.VER_1_0_11;
  }

  public get endpointMetadata(): EndpointMetadataResult {
    this.assertServerMetadata();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return this._state.endpointMetadata!;
  }

  get kid(): string {
    this.assertIssuerData();
    if (!this._state.kid) {
      throw new Error('No value for kid is supplied');
    }
    return this._state.kid;
  }

  get alg(): string {
    this.assertIssuerData();
    if (!this._state.alg) {
      throw new Error('No value for alg is supplied');
    }
    return this._state.alg;
  }

  set clientId(value: string | undefined) {
    this._state.clientId = value;
  }

  get clientId(): string | undefined {
    return this._state.clientId;
  }

  public hasAccessTokenResponse(): boolean {
    return !!this._state.accessTokenResponse;
  }

  get accessTokenResponse(): AccessTokenResponse {
    this.assertAccessToken();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return this._state.accessTokenResponse!;
  }

  public getIssuer(): string {
    this.assertIssuerData();
    return this._state.credentialIssuer;
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

  /**
   * Too bad we need a method like this, but EBSI is not exposing metadata
   */
  public isEBSI() {
    if (
      this.credentialOffer?.credential_offer.credentials.find(
        (cred) =>
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          typeof cred !== 'string' && 'trust_framework' in cred && 'name' in cred.trust_framework && cred.trust_framework.name.includes('ebsi'),
      )
    ) {
      return true;
    }
    this.assertIssuerData();
    return this.endpointMetadata.credentialIssuerMetadata?.authorization_endpoint?.includes('ebsi.eu');
  }

  private assertIssuerData(): void {
    if (!this._state.credentialIssuer) {
      throw Error(`No credential issuer value present`);
    } else if (!this._state.credentialOffer && this._state.endpointMetadata && this.issuerSupportedFlowTypes().length === 0) {
      throw Error(`No issuance initiation or credential offer present`);
    }
  }

  private assertServerMetadata(): void {
    if (!this._state.endpointMetadata) {
      throw Error('No server metadata');
    }
  }

  private assertAccessToken(): void {
    if (!this._state.accessTokenResponse) {
      throw Error(`No access token present`);
    }
  }

  private syncAuthorizationRequestOpts(opts?: AuthorizationRequestOpts): AuthorizationRequestOpts {
    let authorizationRequestOpts = { ...this._state?.authorizationRequestOpts, ...opts } as AuthorizationRequestOpts;
    if (!authorizationRequestOpts) {
      // We only set a redirectUri if no options are provided.
      // Note that this only works for mobile apps, that can handle a code query param on the default openid-credential-offer deeplink.
      // Provide your own options if that is not desired!
      authorizationRequestOpts = { redirectUri: `${DefaultURISchemes.CREDENTIAL_OFFER}://` };
    }
    const clientId = authorizationRequestOpts.clientId ?? this._state.clientId;
    // sync clientId
    this._state.clientId = clientId;
    authorizationRequestOpts.clientId = clientId;
    return authorizationRequestOpts;
  }
}
