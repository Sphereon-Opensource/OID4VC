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
  EndpointMetadata,
  OfferedCredentialsWithMetadata,
  OfferedCredentialType,
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
import { RequestFromCredentialSupported, RequestFromInlineCredentialOffer, RequestFromRequestInput } from './CredentialRequestClient';
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

  public async acquireCredentials(
    opts: {
      proofCallbacks: ProofOfPossessionCallbacks;
      kid?: string;
      alg?: Alg | string;
      jti?: string;
    } & (RequestFromCredentialSupported | RequestFromInlineCredentialOffer | RequestFromRequestInput)
  ): Promise<CredentialResponse> {
    const { proofCallbacks, kid, alg, jti, ...requestOptions } = opts;

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

    // Inline credential offers are only supported from v1_0-11
    if ('inlineCredentialOffer' in requestOptions) {
      if (this.version() < OpenId4VCIVersion.VER_1_0_11) {
        throw new Error('Inline credential offers are not supported for versions prior to v1_0-11');
      }
      // TODO: we should do a deep equality check on the inlineCredentialOffer against the inline offers from the credential offer?
      //
    } else if ('credentialSupported' in requestOptions && this.endpointMetadata?.issuerMetadata) {
      // The credentialSupported MUST have an `id` property, because the offer refers to it.
      if (!requestOptions.credentialSupported.id) {
        throw new Error('id is required in the credential supported for versions prior to v1_0-11');
      }

      // Check if format is supported by issuer, and included in offer
      const credentialsSupported = this.getCredentialsSupported(true, requestOptions.credentialSupported.id);
      if (credentialsSupported.length === 0) {
        throw new Error(`Credential ${requestOptions.credentialSupported.id} not supported by issuer ${this.getIssuer()} or has not been offered`);
      }
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
      ...requestOptions,
      proofInput: proofBuilder,
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
   * Return a normalized version of the credentials supported by the issuer. Can optionally filter based on the credentials
   * that were offered, or the type of credentials that are supported.
   *
   *
   * NOTE: for v1_0-08, a single credential id in the issuer metadata could have multiple formats. When retrieving the
   * supported credentials, for v1_0-08, the format is appended to the id if there are multiple formats supported for
   * that credential id. E.g. if the issuer metadata for v1_0-08 contains an entry with key `OpenBadgeCredential` and
   * the supported formats are `jwt_vc-jsonld` and `ldp_vc`, then the id in the credentials supported will be
   * `OpenBadgeCredential-jwt_vc-jsonld` and `OpenBadgeCredential-ldp_vc`, even though the offered credential is simply
   * `OpenBadgeCredential`.
   *
   * NOTE: this method only returns the credentials supported by the issuer metadata. It does not take into account the inline
   * credentials offered. Use {@link getOfferedCredentialsWithMetadata} to get both the inline and referenced offered credentials.
   */
  getCredentialsSupported(restrictToOfferIds: boolean, credentialSupportedId?: string): CredentialSupported[] {
    const offeredIds = this.getOfferedCredentials().filter((c): c is string => typeof c === 'string');

    const credentialSupportedIds = restrictToOfferIds ? offeredIds : undefined;

    const credentialsSupported = getSupportedCredentials({
      issuerMetadata: this.endpointMetadata.issuerMetadata,
      version: this.version(),
      credentialSupportedIds,
    });

    return credentialSupportedId
      ? credentialsSupported.filter(
          (credentialSupported) =>
            credentialSupported.id === credentialSupportedId || credentialSupported.id === `${credentialSupportedId}-${credentialSupported.format}`
        )
      : credentialsSupported;
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
  getOfferedCredentialsWithMetadata(): Array<OfferedCredentialsWithMetadata> {
    const offeredCredentials: Array<OfferedCredentialsWithMetadata> = [];

    for (const offeredCredential of this.getOfferedCredentials()) {
      // If the offeredCredential is a string, it references a supported credential in the issuer metadata
      if (typeof offeredCredential === 'string') {
        const credentialsSupported = this.getCredentialsSupported(false, offeredCredential);

        // Make sure the issuer metadata includes the offered credential.
        if (credentialsSupported.length === 0) {
          throw new Error(`Offered credential '${offeredCredential}' is not present in the credentials_supported of the issuer metadata`);
        }

        offeredCredentials.push(
          ...credentialsSupported.map((credentialSupported) => {
            return { credentialSupported, type: OfferedCredentialType.CredentialSupported } as const;
          })
        );
      }
      // Otherwise it's an inline credential offer that does not reference a supported credential in the issuer metadata
      else {
        // TODO: we could transform the inline offer to the `CredentialSupported` format, but we'll only be able to populate
        // the `format`, `types` and `@context` fields. It's not really clear how to determine the supported did methods,
        // signature suites, etc.. for these inline credentials.
        // We should also add a property to indicate to the user that this is an inline credential offer.
        //  if (offeredCredential.format === 'jwt_vc_json') {
        //    const supported = {
        //      format: offeredCredential.format,
        //      types: offeredCredential.types,
        //    } satisfies CredentialSupportedJwtVcJson;
        //  } else if (offeredCredential.format === 'jwt_vc_json-ld' || offeredCredential.format === 'ldp_vc') {
        //    const supported = {
        //      format: offeredCredential.format,
        //      '@context': offeredCredential.credential_definition['@context'],
        //      types: offeredCredential.credential_definition.types,
        //    } satisfies CredentialSupported;
        //  }
        offeredCredentials.push({ inlineCredentialOffer: offeredCredential, type: OfferedCredentialType.InlineCredentialOffer } as const);
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
