import {
  AccessTokenResponse,
  Alg,
  AuthorizationRequest,
  AuthzFlowType,
  CodeChallengeMethod,
  CredentialMetadata,
  CredentialOfferRequestWithBaseUrl,
  CredentialResponse,
  CredentialsSupported,
  EndpointMetadata,
  ProofOfPossessionCallbacks,
  ResponseType,
} from '@sphereon/openid4vci-common';
import {CredentialFormat} from '@sphereon/ssi-types';
import Debug from 'debug';

import {AccessTokenClient} from './AccessTokenClient';
import {CredentialOffer} from './CredentialOffer';
import {CredentialRequestClientBuilder} from './CredentialRequestClientBuilder';
import {MetadataClient} from './MetadataClient';
import {ProofOfPossessionBuilder} from './ProofOfPossessionBuilder';
import {convertJsonToURI} from './functions';

const debug = Debug('sphereon:openid4vci:flow');

interface AuthDetails {
  type: 'openid_credential' | string;
  locations?: string | string[];
  format: CredentialFormat | CredentialFormat[];

  [s: string]: unknown;
}

interface AuthRequestOpts {
  clientId: string;
  codeChallenge: string;
  codeChallengeMethod: CodeChallengeMethod;
  authorizationDetails?: AuthDetails | AuthDetails[];
  redirectUri: string;
  scope?: string;
}

export class OpenID4VCIClient {
  private readonly _flowType: AuthzFlowType;
  private readonly _credentialOffer: CredentialOfferRequestWithBaseUrl;
  private _clientId?: string;
  private _kid: string | undefined;
  private _alg: Alg | string | undefined;
  private _serverMetadata: EndpointMetadata | undefined;
  private _accessTokenResponse: AccessTokenResponse | undefined;

  private constructor(
    credentialOffer: CredentialOfferRequestWithBaseUrl,
    flowType: AuthzFlowType,
    kid?: string,
    alg?: Alg | string,
    clientId?: string
  ) {
    this._flowType = flowType;
    this._credentialOffer = credentialOffer;
    this._kid = kid;
    this._alg = alg;
    this._clientId = clientId;
  }

  public static async fromURI({
    uri,
    flowType,
    kid,
    alg,
    retrieveServerMetadata,
    clientId,
  }: {
    uri: string;
    flowType: AuthzFlowType;
    kid?: string;
    alg?: Alg | string;
    retrieveServerMetadata?: boolean;
    clientId?: string;
  }): Promise<OpenID4VCIClient> {
    const client = new OpenID4VCIClient(CredentialOffer.fromURI(uri), flowType, kid, alg, clientId);
    // noinspection PointlessBooleanExpressionJS
    if (retrieveServerMetadata !== false) {
      await client.retrieveServerMetadata();
    }
    return client;
  }

  public async retrieveServerMetadata(): Promise<EndpointMetadata> {
    this.assertIssuerData();
    if (!this._serverMetadata) {
      this._serverMetadata = await MetadataClient.retrieveAllMetadataFromCredentialOffer(this._credentialOffer);
    }
        return this._serverMetadata;
  }

  public createAuthorizationRequestUrl({
    clientId,
    codeChallengeMethod,
    codeChallenge,
    authorizationDetails,
    redirectUri,
    scope,
  }: AuthRequestOpts): string {
    // Scope and authorization_details can be used in the same authorization request
    // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-23#name-relationship-to-scope-param
    if (!scope && !authorizationDetails) {
      throw Error('Please provide a scope or authorization_details');
    }

    if (!this._serverMetadata?.openid4vci_metadata?.authorization_endpoint) {
      throw Error('Server metadata does not contain authorization endpoint');
    }

    // add 'openid' scope if not present
    if (scope && !scope.includes('openid')) {
      scope = `openid ${scope}`;
    }

    const queryObj: AuthorizationRequest = {
      response_type: ResponseType.AUTH_CODE,
      client_id: clientId,
      code_challenge_method: codeChallengeMethod,
      code_challenge: codeChallenge,
      authorization_details: JSON.stringify(this.handleAuthorizationDetails(authorizationDetails)),
      redirect_uri: redirectUri,
      scope: scope,
    };

    return convertJsonToURI(queryObj, {
      baseUrl: this._serverMetadata.openid4vci_metadata.authorization_endpoint,
      uriTypeProperties: ['redirect_uri', 'scope', 'authorization_details'],
    });
  }

  private handleAuthorizationDetails(authorizationDetails?: AuthDetails | AuthDetails[]): AuthDetails | AuthDetails[] | undefined {
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
      (this.serverMetadata.openid4vci_metadata?.authorization_server || this.serverMetadata.openid4vci_metadata?.authorization_endpoint)
    ) {
      if (authorizationDetails.locations) {
        if (Array.isArray(authorizationDetails.locations)) {
          (authorizationDetails.locations as string[]).push(this.serverMetadata.issuer);
        } else {
          authorizationDetails.locations = [authorizationDetails.locations as string, this.serverMetadata.issuer];
        }
      } else {
        authorizationDetails.locations = this.serverMetadata.issuer;
      }
    }
    return authorizationDetails;
  }

  public async acquireAccessToken({
    pin,
    clientId,
    codeVerifier,
    code,
    redirectUri,
  }: {
    pin?: string;
    clientId?: string;
    codeVerifier?: string;
    code?: string;
    redirectUri?: string;
  }): Promise<AccessTokenResponse> {
    this.assertIssuerData();
    if (clientId) {
      this._clientId = clientId;
    }
    if (!this._accessTokenResponse) {
      const accessTokenClient = new AccessTokenClient();

      const response = await accessTokenClient.acquireAccessToken({
        credentialOffer: this.credentialOffer,
        metadata: this._serverMetadata,
        pin,
        codeVerifier,
        code,
        redirectUri,
        asOpts: { clientId: this.clientId },
      });

      if (response.errorBody) {
        debug(`Access token error:\r\n${response.errorBody}`);
        throw Error(
          `Retrieving an access token from ${
            this._serverMetadata?.token_endpoint
          } for issuer ${this.getIssuer()} failed with status: ${response.origResponse.status}`
        );
      } else if (!response.successBody) {
        debug(`Access token error. No succes body`);
        throw Error(
          `Retrieving an access token from ${
            this._serverMetadata?.token_endpoint
          } for issuer ${this.getIssuer()} failed as there was no success response body`
        );
      }
      this._accessTokenResponse = response.successBody;
    }

    return this._accessTokenResponse;
  }

  public async acquireCredentials({
    credentialType,
    proofCallbacks,
    format,
    kid,
    alg,
    jti,
  }: {
    credentialType: string | string[];
    proofCallbacks: ProofOfPossessionCallbacks;
    format?: CredentialFormat | CredentialFormat[];
    kid?: string;
    alg?: Alg | string;
    jti?: string;
  }): Promise<CredentialResponse> {
    if (alg) {
      this._alg = alg;
    }
    if (kid) {
      this._kid = kid;
    }

    const requestBuilder = CredentialRequestClientBuilder.fromCredentialOffer({
      credentialOffer: this.credentialOffer,
        metadata: this.serverMetadata,
      });
    requestBuilder.withToken(this.accessTokenResponse.access_token);
    if (this.serverMetadata?.openid4vci_metadata) {
      const metadata = this.serverMetadata.openid4vci_metadata;
      const types = Array.isArray(credentialType) ? credentialType : [credentialType];
      if (types.some((type) => !metadata.credentials_supported || !metadata.credentials_supported[type])) {
        throw Error(`Not all credential types ${JSON.stringify(credentialType)} are supported by issuer ${this.getIssuer()}`);
      }
      // todo: Format check? We might end up with some disjoint type / format combinations supported by the server
    }
    const credentialRequestClient = requestBuilder.build();
    const proofBuilder = ProofOfPossessionBuilder.fromAccessTokenResponse({
      accessTokenResponse: this.accessTokenResponse,
      callbacks: proofCallbacks,
    })
      .withIssuer(this.getIssuer())
      .withAlg(this.alg)
      .withClientId(this.clientId)
      .withKid(this.kid);

    if (jti) {
      proofBuilder.withJti(jti);
    }
    const response = await credentialRequestClient.acquireCredentialsUsingProof({
      proofInput: proofBuilder,
      credentialType,
      format,
    });
    if (response.errorBody) {
      debug(`Credential request error:\r\n${response.errorBody}`);
      throw Error(
        `Retrieving a credential from ${
          this._serverMetadata?.credential_endpoint
        } for issuer ${this.getIssuer()} failed with status: ${response.origResponse.status}`
      );
    } else if (!response.successBody) {
      debug(`Credential request error. No success body`);
      throw Error(
        `Retrieving a credential from ${
          this._serverMetadata?.credential_endpoint
        } for issuer ${this.getIssuer()} failed as there was no success response body`
      );
    }
    return response.successBody;
  }

  getCredentialsSupported(restrictToInitiationTypes: boolean): CredentialsSupported {
    const credentialsSupported = this.serverMetadata?.openid4vci_metadata?.credentials_supported;
    if (!credentialsSupported) {
      return {};
    } else if (restrictToInitiationTypes === false) {
      return credentialsSupported;
    }
    const initiationTypes = this.getCredentialTypes();
    const supported: CredentialsSupported = {};
    for (const [key, value] of Object.entries(credentialsSupported)) {
      if (initiationTypes.includes(key)) {
        supported[key] = value;
      }
    }
    return supported;
  }

  getCredentialMetadata(type: string): CredentialMetadata {
    return this.getCredentialsSupported(false)[type];
  }

  getCredentialTypes(): string[] {
    return typeof this.credentialOffer.request.credential_type === 'string'
        ? [this.credentialOffer.request.credential_type]
        : this.credentialOffer.request.credential_type;
  }

  get flowType(): AuthzFlowType {
    return this._flowType;
  }

  get credentialOffer(): CredentialOfferRequestWithBaseUrl {
    return this._credentialOffer;
  }

  public get serverMetadata(): EndpointMetadata {
    this.assertServerMetadata();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return this._serverMetadata!;
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

  get clientId(): string {
    if (!this._clientId) {
      throw Error('No client id present');
    }
    return this._clientId;
  }

  get accessTokenResponse(): AccessTokenResponse {
    this.assertAccessToken();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return this._accessTokenResponse!;
  }

  public getIssuer(): string {
    this.assertIssuerData();
    return this._serverMetadata ? this.serverMetadata.issuer : this.getIssuer();
  }

  public getAccessTokenEndpoint(): string {
    this.assertIssuerData();
    return this.serverMetadata
      ? this.serverMetadata.token_endpoint
      : AccessTokenClient.determineTokenURL({ issuerOpts: { issuer: this.getIssuer() } });
  }

  public getCredentialEndpoint(): string {
    this.assertIssuerData();
    return this.serverMetadata ? this.serverMetadata.credential_endpoint : `${this.getIssuer()}/credential`;
  }

  private assertIssuerData(): void {
    if (!this._credentialOffer) {
      throw Error(`No issuance initiation or credential offer present`);
    }
  }

  private assertServerMetadata(): void {
    if (!this._serverMetadata) {
      throw Error('No server metadata');
    }
  }

  private assertAccessToken(): void {
    if (!this._accessTokenResponse) {
      throw Error(`No access token present`);
    }
  }
}
