import {
  AccessTokenResponse,
  Alg,
  AuthorizationRequestV1_0_09,
  AuthzFlowType,
  CodeChallengeMethod,
  CredentialOfferFormat,
  CredentialOfferPayloadV1_0_08,
  CredentialOfferRequestWithBaseUrl,
  CredentialResponse,
  CredentialSupported,
  CredentialSupportedTypeV1_0_08,
  EndpointMetadata,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  OpenIDResponse,
  ProofOfPossessionCallbacks,
  PushedAuthorizationResponse,
  ResponseType,
} from '@sphereon/oid4vci-common';
import { getSupportedCredentials } from '@sphereon/oid4vci-common/dist/functions/IssuerMetadataUtils';
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
  private _endpointMetadata: EndpointMetadata | undefined;
  private _accessTokenResponse: AccessTokenResponse | undefined;

  private constructor(
    credentialOffer: CredentialOfferRequestWithBaseUrl,
    flowType: AuthzFlowType,
    kid?: string,
    alg?: Alg | string,
    clientId?: string
  ) {
    if (!credentialOffer.supportedFlows.includes(flowType)) {
      throw Error(`Flows ${flowType} is not supported by issuer ${credentialOffer.credential_offer_uri}`);
    }
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
    resolveOfferUri,
  }: {
    uri: string;
    flowType: AuthzFlowType;
    kid?: string;
    alg?: Alg | string;
    retrieveServerMetadata?: boolean;
    resolveOfferUri?: boolean;
    clientId?: string;
  }): Promise<OpenID4VCIClient> {
    const client = new OpenID4VCIClient(await CredentialOfferClient.fromURI(uri, { resolve: resolveOfferUri }), flowType, kid, alg, clientId);

    if (retrieveServerMetadata === undefined || retrieveServerMetadata) {
      await client.retrieveServerMetadata();
    }
    return client;
  }

  public async retrieveServerMetadata(): Promise<EndpointMetadata> {
    this.assertIssuerData();
    if (!this._endpointMetadata) {
      this._endpointMetadata = await MetadataClient.retrieveAllMetadataFromCredentialOffer(this.credentialOffer);
    }
    return this.endpointMetadata;
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
    // todo: handling this because of the support for v1_0-08
    if (this._endpointMetadata && this._endpointMetadata.issuerMetadata && 'authorization_endpoint' in this._endpointMetadata.issuerMetadata) {
      this._endpointMetadata.authorization_endpoint = this._endpointMetadata.issuerMetadata.authorization_endpoint as string;
    }
    if (!this._endpointMetadata?.authorization_endpoint) {
      throw Error('Server metadata does not contain authorization endpoint');
    }

    // add 'openid' scope if not present
    if (scope && !scope.includes('openid')) {
      scope = `openid ${scope}`;
    }

    //fixme: handle this for v11
    const queryObj = {
      response_type: ResponseType.AUTH_CODE,
      client_id: clientId,
      code_challenge_method: codeChallengeMethod,
      code_challenge: codeChallenge,
      authorization_details: JSON.stringify(this.handleAuthorizationDetails(authorizationDetails)),
      redirect_uri: redirectUri,
      scope: scope,
    } as AuthorizationRequestV1_0_09;

    return convertJsonToURI(queryObj, {
      baseUrl: this._endpointMetadata.authorization_endpoint,
      uriTypeProperties: ['redirect_uri', 'scope', 'authorization_details'],
      version: this.version(),
    });
  }

  public async acquirePushedAuthorizationRequestURI({
    clientId,
    codeChallengeMethod,
    codeChallenge,
    authorizationDetails,
    redirectUri,
    scope,
  }: AuthRequestOpts): Promise<OpenIDResponse<PushedAuthorizationResponse>> {
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
      !this._endpointMetadata?.issuerMetadata ||
      !('pushed_authorization_request_endpoint' in this._endpointMetadata.issuerMetadata) ||
      typeof this._endpointMetadata.issuerMetadata.pushed_authorization_request_endpoint !== 'string'
    ) {
      throw Error('Server metadata does not contain pushed authorization request endpoint');
    }
    const parEndpoint: string = this._endpointMetadata.issuerMetadata.pushed_authorization_request_endpoint;

    // add 'openid' scope if not present
    if (scope && !scope.includes('openid')) {
      scope = `openid ${scope}`;
    }

    //fixme: handle this for v11
    const queryObj: AuthorizationRequestV1_0_09 = {
      response_type: ResponseType.AUTH_CODE,
      client_id: clientId,
      code_challenge_method: codeChallengeMethod,
      code_challenge: codeChallenge,
      authorization_details: JSON.stringify(this.handleAuthorizationDetails(authorizationDetails)),
      redirect_uri: redirectUri,
      scope: scope,
    };
    return await formPost(parEndpoint, JSON.stringify(queryObj));
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
    if (authorizationDetails && (this.endpointMetadata.issuerMetadata?.authorization_server || this.endpointMetadata.authorization_endpoint)) {
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
          }`
        );
      } else if (!response.successBody) {
        debug(`Access token error. No success body`);
        throw Error(
          `Retrieving an access token from ${
            this._endpointMetadata?.token_endpoint
          } for issuer ${this.getIssuer()} failed as there was no success response body`
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
    alg,
    jti,
  }: {
    credentialTypes: string | string[];
    proofCallbacks: ProofOfPossessionCallbacks;
    format?: CredentialFormat | OID4VCICredentialFormat;
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
      metadata: this.endpointMetadata,
    });
    requestBuilder.withTokenFromResponse(this.accessTokenResponse);
    if (this.endpointMetadata?.issuerMetadata) {
      const metadata = this.endpointMetadata.issuerMetadata;
      const types = Array.isArray(credentialTypes) ? credentialTypes : [credentialTypes];
      if (metadata.credentials_supported && Array.isArray(metadata.credentials_supported)) {
        for (const type of types) {
          let typeSupported = false;
          for (const credentialSupported of metadata.credentials_supported) {
            if (!credentialSupported.types || credentialSupported.types.length === 0) {
              throw Error('types is required in the credentials supported');
            }
            if (credentialSupported.types.indexOf(type) != -1) {
              typeSupported = true;
            }
          }
          if (!typeSupported) {
            throw Error(`Not all credential types ${JSON.stringify(credentialTypes)} are supported by issuer ${this.getIssuer()}`);
          }
        }
      } else if (metadata.credentials_supported && !Array.isArray(metadata.credentials_supported)) {
        const credentialsSupported = metadata.credentials_supported as CredentialSupportedTypeV1_0_08;
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
      .withAlg(this.alg)
      .withKid(this.kid);

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
      debug(`Credential request error:\r\n${response.errorBody}`);
      throw Error(
        `Retrieving a credential from ${this._endpointMetadata?.credential_endpoint} for issuer ${this.getIssuer()} failed with status: ${
          response.origResponse.status
        }`
      );
    } else if (!response.successBody) {
      debug(`Credential request error. No success body`);
      throw Error(
        `Retrieving a credential from ${
          this._endpointMetadata?.credential_endpoint
        } for issuer ${this.getIssuer()} failed as there was no success response body`
      );
    }
    return response.successBody;
  }

  /**
   * Retrieve a supported credential by it's id. This is a convenience method that takes into account difference between the
   * different versions of the oid4vci specification.
   *
   * NOTE: for v1_0-08, a single credential id in the issuer metadata could have multiple formats. When retrieving the
   * supported credentials (using {@link getCredentialsSupported}), for v1_0-08, the format is appended to the id if
   * there are multiple formats supported for that credential id. E.g. if the issuer metadata for v1_0-08 contains an
   * entry with key `OpenBadgeCredential` and the supported formats are `jwt_vc-jsonld` and `ldp_vc`, then the id
   * in the credentials supported will be `OpenBadgeCredential-jwt_vc-jsonld` and `OpenBadgeCredential-ldp_vc`, even though
   * the offered credential is simply `OpenBadgeCredential`. This method takes this into account.
   */
  getCredentialsSupportedById(credentialSupportedId: string, format?: CredentialFormat): CredentialSupported[] {
    return this.getCredentialMetadata(credentialSupportedId).filter((credentialSupported) => credentialSupported.format === format);
  }

  /**
   * Return a normalized version of the credentials supported by the issuer. Can optionally filter based on the credentials
   * that were offered, or the type of credentials that are supported.
   *
   *
   * NOTE: for v1_0-08, a single credential id in the issuer metadata could have multiple formats. When retrieving the
   * supported credentials, for v1_0-08, the format is appended to the id if there are multiple formats supported for
   * that credential id. E.g. if the issuer metadata for v1_0-08 contains an entry with key `OpenBadgeCredential` and
   * the supported formats are `jwt_vc-jsonld` and `ldp_vc`, then the id in the credentials supported will be
   * `OpenBadgeCredential-jwt_vc-jsonld` and `OpenBadgeCredential-ldp_vc`, even though the offered credential is simply
   * `OpenBadgeCredential`. You can use {@link getCredentialsSupportedById} to get the correct supported credential.
   *
   * NOTE: this method only returns the credentials supported by the issuer metadata. It does not take into account the
   * credentials offered. Use {@link getOfferedCredentialsWithMetadata} to get both the inline and referenced offered credentials.
   */
  getCredentialsSupported(restrictToInitiationTypes: boolean, supportedType?: string): CredentialSupported[] {
    return getSupportedCredentials({
      issuerMetadata: this.endpointMetadata.issuerMetadata,
      version: this.version(),
      supportedType,
      credentialTypes: restrictToInitiationTypes ? this.getOfferedCredentials().filter((c): c is string => typeof c === 'string') : undefined,
    });
    /*//FIXME: delegate to getCredentialsSupported from IssuerMetadataUtils
    let credentialsSupported = this.endpointMetadata?.issuerMetadata?.credentials_supported

    if (this.version() === OpenId4VCIVersion.VER_1_0_08 || typeof credentialsSupported === 'object') {
      const issuerMetadata = this.endpointMetadata.issuerMetadata as IssuerMetadataV1_0_08
      const v8CredentialsSupported = issuerMetadata.credentials_supported
      credentialsSupported = []
      credentialsSupported = Object.entries(v8CredentialsSupported).map((key, value) => )

    }


    if (!credentialsSupported) {
      return []
    } else if (!restrictToInitiationTypes) {
      return credentialsSupported
    }



    /!**
     * the following (not array part is a legacy code from version 1_0-08 which jff implementors used)
     *!/
    if (!Array.isArray(credentialsSupported)) {
      const credentialsSupportedV8: CredentialSupportedV1_0_08 = credentialsSupported as CredentialSupportedV1_0_08;
      const initiationTypes = supportedType ? [supportedType] : this.getCredentialTypes();
      const supported: IssuerCredentialSubject = {};
      for (const [key, value] of Object.entries(credentialsSupportedV8)) {
        if (initiationTypes.includes(key)) {
          supported[key] = value;
        }
      }
      // todo: fix this later. we're returning CredentialSupportedV1_0_08 as a list of CredentialSupported (for v09 onward)
      return supported as unknown as CredentialSupported[];
    }
    const initiationTypes = supportedType ? [supportedType] : this.getCredentialTypes()
    const credentialSupportedOverlap: CredentialSupported[] = []
    for (const supported of credentialsSupported) {
      const supportedTypeOverlap: string[] = []
      for (const type of supported.types) {
        initiationTypes.includes(type)
        supportedTypeOverlap.push(type)
      }
      if (supportedTypeOverlap.length > 0) {
        credentialSupportedOverlap.push({
          ...supported,
          types: supportedTypeOverlap
        })
      }
    }
    return credentialSupportedOverlap as CredentialSupported[]*/
  }

  getCredentialMetadata(type: string): CredentialSupported[] {
    return this.getCredentialsSupported(false, type);
  }

  // todo https://sphereon.atlassian.net/browse/VDX-184
  /**
   * Returns all entries from the credential offer. This includes both 'id' entries that reference a supported credential in the issuer metadata,
   * as well as inline credential offers that do not reference a supported credential in the issuer metadata.
   */
  getOfferedCredentials(): Array<string | CredentialOfferFormat> {
    if (this.credentialOffer.version < OpenId4VCIVersion.VER_1_0_11) {
      const credentialOffer = this.credentialOffer.original_credential_offer as CredentialOfferPayloadV1_0_08;

      return typeof credentialOffer.credential_type === 'string' ? [credentialOffer.credential_type] : credentialOffer.credential_type;
    } else {
      return this.credentialOffer.credential_offer.credentials;
    }
  }

  /**
   * Returns all entries from the credential offer with the associated metadata resolved. For inline entries, the offered credential object
   * is included directly. For 'id' entries, the associated `credentials_supported` object is resolved from the issuer metadata.
   *
   * NOTE: for v1_0-08, a single credential id in the issuer metadata could have multiple formats. This means that the returned value
   * from this method could contain multiple entries for a single credential id, but with different formats. This is detectable as the
   * id will be the `<credentialId>-<format>`.
   */
  getOfferedCredentialsWithMetadata(): Array<CredentialSupported | CredentialOfferFormat> {
    const offeredCredentials: Array<CredentialSupported | CredentialOfferFormat> = [];

    for (const offeredCredential of this.getOfferedCredentials()) {
      // If the offeredCredential is a string, it references a supported credential in the issuer metadata
      if (typeof offeredCredential === 'string') {
        offeredCredentials.push(...this.getCredentialsSupportedById(offeredCredential));
      }
      // Otherwise it's an inline credential offer that does not reference a supported credential in the issuer metadata
      else {
        offeredCredentials.push(offeredCredential);
      }
    }

    return offeredCredentials;
  }

  get flowType(): AuthzFlowType {
    return this._flowType;
  }

  issuerSupportedFlowTypes(): AuthzFlowType[] {
    return this.credentialOffer.supportedFlows;
  }

  get credentialOffer(): CredentialOfferRequestWithBaseUrl {
    return this._credentialOffer;
  }

  public version(): OpenId4VCIVersion {
    return this.credentialOffer.version;
  }

  public get endpointMetadata(): EndpointMetadata {
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
    /*if (!this._clientId) {
      throw Error('No client id present');
    }*/
    return this._clientId;
  }

  get accessTokenResponse(): AccessTokenResponse {
    this.assertAccessToken();
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    return this._accessTokenResponse!;
  }

  public getIssuer(): string {
    this.assertIssuerData();
    return this._endpointMetadata ? this.endpointMetadata.issuer : this.getIssuer();
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
    if (!this._credentialOffer) {
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
}
