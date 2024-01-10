import {
  AccessTokenResponse,
  Alg,
  AuthzFlowType,
  CodeChallengeMethod,
  CredentialOfferRequestWithBaseUrl,
  CredentialResponse,
  CredentialSupported,
  EndpointMetadataResult,
  getIssuerFromCredentialOfferPayload,
  JsonURIMode,
  JWK,
  KID_JWK_X5C_ERROR,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  ProofOfPossessionCallbacks,
  PushedAuthorizationResponse,
  ResponseType
} from '@sphereon/oid4vci-common';
import { getSupportedCredentials, getTypesFromCredentialSupported } from '@sphereon/oid4vci-common/dist/functions/IssuerMetadataUtils';
import { CredentialFormat } from '@sphereon/ssi-types';
import Debug from 'debug';

import { AccessTokenClient } from './AccessTokenClient';
import { CredentialOfferClient } from './CredentialOfferClient';
import { CredentialRequestClientBuilder } from './CredentialRequestClientBuilder';
import { MetadataClient } from './MetadataClient';
import { ProofOfPossessionBuilder } from './ProofOfPossessionBuilder';
import { convertJsonToURI, formPost } from './functions';

const debug = Debug('sphereon:oid4vci');

interface AuthDetails {
  type: 'openid_credential' | string;
  locations?: string | string[];
  format: CredentialFormat | CredentialFormat[];

  [s: string]: unknown;
}

interface AuthRequestOpts {
  codeChallenge: string;
  codeChallengeMethod?: CodeChallengeMethod;
  authorizationDetails?: AuthDetails | AuthDetails[];
  redirectUri: string;
  scope?: string;
}

export class OpenID4VCIClient {
  private readonly _credentialOffer?: CredentialOfferRequestWithBaseUrl;
  private _credentialIssuer: string;
  private _clientId?: string;
  private _kid: string | undefined;
  private _jwk: JWK | undefined;
  private _alg: Alg | string | undefined;
  private _endpointMetadata: EndpointMetadataResult | undefined;
  private _accessTokenResponse: AccessTokenResponse | undefined;

  private constructor({
    credentialOffer,
    clientId,
    kid,
    alg,
    credentialIssuer,
  }: {
    credentialOffer?: CredentialOfferRequestWithBaseUrl;
    kid?: string;
    alg?: Alg | string;
    clientId?: string;
    credentialIssuer?: string;
  }) {
    this._credentialOffer = credentialOffer;
    const issuer = credentialIssuer ?? (credentialOffer ? getIssuerFromCredentialOfferPayload(credentialOffer.credential_offer) : undefined);
    if (!issuer) {
      throw Error('No credential issuer supplied or deduced from offer');
    }
    this._credentialIssuer = issuer;
    this._kid = kid;
    this._alg = alg;
    this._clientId = clientId;
  }

  public static async fromCredentialIssuer({
    kid,
    alg,
    retrieveServerMetadata,
    clientId,
    credentialIssuer,
  }: {
    credentialIssuer: string;
    kid?: string;
    alg?: Alg | string;
    retrieveServerMetadata?: boolean;
    clientId?: string;
  }) {
    const client = new OpenID4VCIClient({ kid, alg, clientId, credentialIssuer });
    if (retrieveServerMetadata === undefined || retrieveServerMetadata) {
      await client.retrieveServerMetadata();
    }
    return client;
  }

  public static async fromURI({
    uri,
    kid,
    alg,
    retrieveServerMetadata,
    clientId,
    resolveOfferUri,
  }: {
    uri: string;
    kid?: string;
    alg?: Alg | string;
    retrieveServerMetadata?: boolean;
    resolveOfferUri?: boolean;
    clientId?: string;
  }): Promise<OpenID4VCIClient> {
    const client = new OpenID4VCIClient({
      credentialOffer: await CredentialOfferClient.fromURI(uri, { resolve: resolveOfferUri }),
      kid,
      alg,
      clientId,
    });

    if (retrieveServerMetadata === undefined || retrieveServerMetadata) {
      await client.retrieveServerMetadata();
    }
    return client;
  }

  public async retrieveServerMetadata(): Promise<EndpointMetadataResult> {
    this.assertIssuerData();
    if (!this._endpointMetadata) {
      if (this.credentialOffer) {
        this._endpointMetadata = await MetadataClient.retrieveAllMetadataFromCredentialOffer(this.credentialOffer);
      } else if (this._credentialIssuer) {
        this._endpointMetadata = await MetadataClient.retrieveAllMetadata([this._credentialIssuer]); // TODO multi-server support?
      } else {
        throw Error(`Cannot retrieve issuer metadata without either a credential offer, or issuer value`);
      }
    }
    return this.endpointMetadata;
  }

  // todo: Unify this method with the par method

  public createAuthorizationRequestUrl({ codeChallengeMethod, codeChallenge, authorizationDetails, redirectUri, scope }: AuthRequestOpts): string {
    // Scope and authorization_details can be used in the same authorization request
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-23#name-relationship-to-scope-param
    if (!scope && !authorizationDetails) {
      if (!this.credentialOffer) {
        throw Error('Please provide a scope or authorization_details');
      }
      const creds = this.credentialOffer.credential_offer.credentials;

      authorizationDetails = creds
        .flatMap((cred) => (typeof cred === 'string' ? this.getCredentialsSupported(true) : (cred as CredentialSupported)))
        .map((cred) => {
          return {
            ...cred,
            type: 'openid_credential',
            locations: [this._credentialIssuer],
            format: cred.format,
          } satisfies AuthDetails;
        });
      if (authorizationDetails.length === 0) {
        throw Error(`Could not create authorization details from credential offer. Please pass in explicit details`);
      }
    }
    // todo: Probably can go with current logic in MetadataClient who will always set the authorization_endpoint when found
    //  handling this because of the support for v1_0-08
    if (
      this._endpointMetadata &&
      this._endpointMetadata.credentialIssuerMetadata &&
      'authorization_endpoint' in this._endpointMetadata.credentialIssuerMetadata
    ) {
      this._endpointMetadata.authorization_endpoint = this._endpointMetadata.credentialIssuerMetadata.authorization_endpoint as string;
    }
    if (!this._endpointMetadata?.authorization_endpoint) {
      throw Error('Server metadata does not contain authorization endpoint');
    }

    // add 'openid' scope if not present
    if (!scope?.includes('openid')) {
      scope = ['openid', scope].filter((s) => !!s).join(' ');
    }

    const queryObj: { [key: string]: string } = {
      response_type: ResponseType.AUTH_CODE,
      code_challenge_method: codeChallengeMethod ?? CodeChallengeMethod.SHA256,
      code_challenge: codeChallenge,
      authorization_details: JSON.stringify(this.handleAuthorizationDetails(authorizationDetails)),
      redirect_uri: redirectUri,
      scope: scope,
    };

    if (this.clientId) {
      queryObj['client_id'] = this.clientId;
    }

    if (this.credentialOffer?.issuerState) {
      queryObj['issuer_state'] = this.credentialOffer.issuerState;
    }

    return convertJsonToURI(queryObj, {
      baseUrl: this._endpointMetadata.authorization_endpoint,
      uriTypeProperties: ['redirect_uri', 'scope', 'authorization_details', 'issuer_state'],
      mode: JsonURIMode.X_FORM_WWW_URLENCODED,
      // We do not add the version here, as this always needs to be form encoded
    });
  }

  // todo: Unify this method with the create auth request url method
  public async acquirePushedAuthorizationRequestURI({
    codeChallengeMethod,
    codeChallenge,
    authorizationDetails,
    redirectUri,
    scope,
  }: AuthRequestOpts): Promise<string> {
    // Scope and authorization_details can be used in the same authorization request
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-23#name-relationship-to-scope-param
    if (!scope && !authorizationDetails) {
      throw Error('Please provide a scope or authorization_details');
    }

    // Authorization servers supporting PAR SHOULD include the URL of their pushed authorization request endpoint in their authorization server metadata document
    // Note that the presence of pushed_authorization_request_endpoint is sufficient for a client to determine that it may use the PAR flow.
    // What happens if it doesn't ???
    // let parEndpoint: string
    if (
      !this._endpointMetadata?.credentialIssuerMetadata ||
      !('pushed_authorization_request_endpoint' in this._endpointMetadata.credentialIssuerMetadata) ||
      typeof this._endpointMetadata.credentialIssuerMetadata.pushed_authorization_request_endpoint !== 'string'
    ) {
      throw Error('Server metadata does not contain pushed authorization request endpoint');
    }
    const parEndpoint: string = this._endpointMetadata.credentialIssuerMetadata.pushed_authorization_request_endpoint;

    // add 'openid' scope if not present
    if (!scope?.includes('openid')) {
      scope = ['openid', scope].filter((s) => !!s).join(' ');
    }

    const queryObj: { [key: string]: string } = {
      response_type: ResponseType.AUTH_CODE,
      code_challenge_method: codeChallengeMethod ?? CodeChallengeMethod.SHA256,
      code_challenge: codeChallenge,
      authorization_details: JSON.stringify(this.handleAuthorizationDetails(authorizationDetails)),
      redirect_uri: redirectUri,
      scope: scope,
    };

    if (this.clientId) {
      queryObj['client_id'] = this.clientId;
    }

    if (this.credentialOffer?.issuerState) {
      queryObj['issuer_state'] = this.credentialOffer.issuerState;
    }

    const response = await formPost<PushedAuthorizationResponse>(parEndpoint, new URLSearchParams(queryObj));

    return convertJsonToURI(
      { request_uri: response.successBody?.request_uri },
      {
        baseUrl: this._endpointMetadata.credentialIssuerMetadata.authorization_endpoint,
        uriTypeProperties: ['request_uri'],
        mode: JsonURIMode.X_FORM_WWW_URLENCODED,
      },
    );
  }

  public handleAuthorizationDetails(authorizationDetails?: AuthDetails | AuthDetails[]): AuthDetails | AuthDetails[] | undefined {
    if (authorizationDetails) {
      if (Array.isArray(authorizationDetails)) {
        return authorizationDetails.map((value) => this.handleLocations({ ...value }));
      } else {
        return this.handleLocations({ ...authorizationDetails });
      }
    }
    return authorizationDetails;
  }

  private handleLocations(authorizationDetails: AuthDetails) {
    if (
      authorizationDetails &&
      (this.endpointMetadata.credentialIssuerMetadata?.authorization_servers || this.endpointMetadata.authorization_endpoint)
    ) {
      if (authorizationDetails.locations) {
        if (Array.isArray(authorizationDetails.locations)) {
          (authorizationDetails.locations as string[]).push(this.endpointMetadata.issuer);
        } else {
          authorizationDetails.locations = [authorizationDetails.locations as string, this.endpointMetadata.issuer];
        }
      } else {
        authorizationDetails.locations = this.endpointMetadata.issuer;
      }
    }
    return authorizationDetails;
  }

  public async acquireAccessToken(opts?: {
    pin?: string;
    clientId?: string;
    codeVerifier?: string;
    code?: string;
    redirectUri?: string;
  }): Promise<AccessTokenResponse> {
    const { pin, clientId, codeVerifier, code, redirectUri } = opts ?? {};

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
        codeVerifier,
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
  }: {
    credentialTypes: string | string[];
    proofCallbacks: ProofOfPossessionCallbacks<any>;
    format?: CredentialFormat | OID4VCICredentialFormat;
    kid?: string;
    jwk?: JWK;
    alg?: Alg | string;
    jti?: string;
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
        const credentialsSupported = metadata.credentials_supported as CredentialSupported;
        if (credentialsSupported.format === 'vc+sd-jwt') {
          if (types.some((type) => !metadata.credentials_supported || credentialsSupported.vct === type)) {
            throw Error(`Not all credential types ${JSON.stringify(credentialTypes)} are supported by issuer ${this.getIssuer()}`);
          }
        } else {
          if (types.some((type) => !metadata.credentials_supported || !credentialsSupported.credential_definition.type.includes(type))) {
            throw Error(`Not all credential types ${JSON.stringify(credentialTypes)} are supported by issuer ${this.getIssuer()}`);
          }
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
    format?: (OID4VCICredentialFormat | string) | (OID4VCICredentialFormat | string)[]
  ): CredentialSupported[] {
    return getSupportedCredentials({
      issuerMetadata: this.endpointMetadata.credentialIssuerMetadata,
      version: this.version(),
      format: format,
      types: restrictToInitiationTypes ? this.getCredentialOfferTypes() : undefined
    });
  }

  getCredentialOfferTypes(): string[][] {
    if (!this.credentialOffer) {
      return [];
    }
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

  issuerSupportedFlowTypes(): AuthzFlowType[] {
    return this.credentialOffer?.supportedFlows ?? [AuthzFlowType.AUTHORIZATION_CODE_FLOW];
  }

  get credentialOffer(): CredentialOfferRequestWithBaseUrl | undefined {
    return this._credentialOffer;
  }

  public version(): OpenId4VCIVersion {
    return this.credentialOffer?.version ?? OpenId4VCIVersion.VER_1_0_12;
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

  private assertIssuerData(): void {
    if (!this._credentialOffer && this.issuerSupportedFlowTypes().includes(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW)) {
      throw Error(`No issuance initiation or credential offer present`);
    } else if (!this._credentialIssuer) {
      throw Error(`No credential issuer value present`);
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
}
