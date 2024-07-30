import { createDPoP, CreateDPoPClientOpts, getCreateDPoPOptions } from '@sphereon/oid4vc-common';
import {
  AccessTokenRequest,
  AccessTokenRequestOpts,
  AccessTokenResponse,
  assertedUniformCredentialOffer,
  AuthorizationServerOpts,
  AuthzFlowType,
  convertJsonToURI,
  CredentialOfferV1_0_11,
  CredentialOfferV1_0_13,
  DPoPResponseParams,
  EndpointMetadata,
  formPost,
  getIssuerFromCredentialOfferPayload,
  GrantTypes,
  IssuerOpts,
  JsonURIMode,
  OpenId4VCIVersion,
  OpenIDResponse,
  PRE_AUTH_CODE_LITERAL,
  PRE_AUTH_GRANT_LITERAL,
  TokenErrorResponse,
  toUniformCredentialOfferRequest,
  UniformCredentialOfferPayload,
} from '@sphereon/oid4vci-common';
import { ObjectUtils } from '@sphereon/ssi-types';
import Debug from 'debug';

import { MetadataClientV1_0_13 } from './MetadataClientV1_0_13';
import { createJwtBearerClientAssertion } from './functions';
import { dPoPShouldRetryRequestWithNonce } from './functions/dpopUtil';

const debug = Debug('sphereon:oid4vci:token');

export class AccessTokenClientV1_0_11 {
  public async acquireAccessToken(opts: AccessTokenRequestOpts): Promise<OpenIDResponse<AccessTokenResponse, DPoPResponseParams>> {
    const { asOpts, pin, codeVerifier, code, redirectUri, metadata, createDPoPOpts } = opts;

    const credentialOffer = opts.credentialOffer ? await assertedUniformCredentialOffer(opts.credentialOffer) : undefined;
    const isPinRequired = credentialOffer && this.isPinRequiredValue(credentialOffer.credential_offer);
    const issuer =
      opts.credentialIssuer ??
      (credentialOffer ? getIssuerFromCredentialOfferPayload(credentialOffer.credential_offer) : (metadata?.issuer as string));
    if (!issuer) {
      throw Error('Issuer required at this point');
    }
    const issuerOpts = {
      issuer,
    };

    return await this.acquireAccessTokenUsingRequest({
      accessTokenRequest: await this.createAccessTokenRequest({
        credentialOffer,
        asOpts,
        codeVerifier,
        code,
        redirectUri,
        pin,
        credentialIssuer: issuer,
        metadata,
        additionalParams: opts.additionalParams,
        pinMetadata: opts.pinMetadata,
      }),
      isPinRequired,
      metadata,
      asOpts,
      issuerOpts,
      createDPoPOpts,
    });
  }

  public async acquireAccessTokenUsingRequest({
    accessTokenRequest,
    isPinRequired,
    metadata,
    asOpts,
    createDPoPOpts,
    issuerOpts,
  }: {
    accessTokenRequest: AccessTokenRequest;
    isPinRequired?: boolean;
    metadata?: EndpointMetadata;
    asOpts?: AuthorizationServerOpts;
    issuerOpts?: IssuerOpts;
    createDPoPOpts?: CreateDPoPClientOpts;
  }): Promise<OpenIDResponse<AccessTokenResponse, DPoPResponseParams>> {
    this.validate(accessTokenRequest, isPinRequired);

    const requestTokenURL = AccessTokenClientV1_0_11.determineTokenURL({
      asOpts,
      issuerOpts,
      metadata: metadata
        ? metadata
        : issuerOpts?.fetchMetadata
          ? await MetadataClientV1_0_13.retrieveAllMetadata(issuerOpts.issuer, { errorOnNotFound: false })
          : undefined,
    });

    const useDpop = createDPoPOpts?.dPoPSigningAlgValuesSupported && createDPoPOpts.dPoPSigningAlgValuesSupported.length > 0;
    let dPoP = useDpop ? await createDPoP(getCreateDPoPOptions(createDPoPOpts, requestTokenURL)) : undefined;

    let response = await this.sendAuthCode(requestTokenURL, accessTokenRequest, dPoP ? { headers: { dpop: dPoP } } : undefined);

    let nextDPoPNonce = createDPoPOpts?.jwtPayloadProps.nonce;
    const retryWithNonce = dPoPShouldRetryRequestWithNonce(response);
    if (retryWithNonce.ok && createDPoPOpts) {
      createDPoPOpts.jwtPayloadProps.nonce = retryWithNonce.dpopNonce;

      dPoP = await createDPoP(getCreateDPoPOptions(createDPoPOpts, requestTokenURL));
      response = await this.sendAuthCode(requestTokenURL, accessTokenRequest, dPoP ? { headers: { dpop: dPoP } } : undefined);
      const successDPoPNonce = response.origResponse.headers.get('DPoP-Nonce');

      nextDPoPNonce = successDPoPNonce ?? retryWithNonce.dpopNonce;
    }

    if (response.successBody && createDPoPOpts && createDPoPOpts && response.successBody.token_type !== 'DPoP') {
      throw new Error('Invalid token type returned. Expected DPoP. Received: ' + response.successBody.token_type);
    }
    return {
      ...response,
      params: { ...(nextDPoPNonce && { dpop: { dpopNonce: nextDPoPNonce } }) },
    };
  }

  public async createAccessTokenRequest(opts: Omit<AccessTokenRequestOpts, 'createDPoPOpts'>): Promise<AccessTokenRequest> {
    const { asOpts, pin, codeVerifier, code, redirectUri } = opts;
    const credentialOfferRequest = opts.credentialOffer
      ? await toUniformCredentialOfferRequest(opts.credentialOffer as CredentialOfferV1_0_11 | CredentialOfferV1_0_13)
      : undefined;
    const request: Partial<AccessTokenRequest> = { ...opts.additionalParams };
    const credentialIssuer = opts.credentialIssuer ?? credentialOfferRequest?.credential_offer?.credential_issuer ?? opts.metadata?.issuer;

    if (asOpts?.clientOpts?.clientId) {
      request.client_id = asOpts.clientOpts.clientId;
    }
    await createJwtBearerClientAssertion(request, { ...opts, version: OpenId4VCIVersion.VER_1_0_11, credentialIssuer });

    if (credentialOfferRequest?.supportedFlows.includes(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW)) {
      this.assertNumericPin(this.isPinRequiredValue(credentialOfferRequest.credential_offer), pin);
      request.user_pin = pin;

      request.grant_type = GrantTypes.PRE_AUTHORIZED_CODE;
      // we actually know it is there because of the isPreAuthCode call
      request[PRE_AUTH_CODE_LITERAL] = credentialOfferRequest?.credential_offer.grants?.[PRE_AUTH_GRANT_LITERAL]?.[PRE_AUTH_CODE_LITERAL];

      return request as AccessTokenRequest;
    }

    if (!credentialOfferRequest || credentialOfferRequest.supportedFlows.includes(AuthzFlowType.AUTHORIZATION_CODE_FLOW)) {
      request.grant_type = GrantTypes.AUTHORIZATION_CODE;
      request.code = code;
      request.redirect_uri = redirectUri;

      if (codeVerifier) {
        request.code_verifier = codeVerifier;
      }

      return request as AccessTokenRequest;
    }

    throw new Error('Credential offer request does not follow neither pre-authorized code nor authorization code flow requirements.');
  }

  private assertPreAuthorizedGrantType(grantType: GrantTypes): void {
    if (GrantTypes.PRE_AUTHORIZED_CODE !== grantType) {
      throw new Error('grant type must be PRE_AUTH_GRANT_LITERAL');
    }
  }

  private assertAuthorizationGrantType(grantType: GrantTypes): void {
    if (GrantTypes.AUTHORIZATION_CODE !== grantType) {
      throw new Error("grant type must be 'authorization_code'");
    }
  }

  private isPinRequiredValue(requestPayload: UniformCredentialOfferPayload): boolean {
    let isPinRequired = false;
    if (!requestPayload) {
      throw new Error(TokenErrorResponse.invalid_request);
    }
    const issuer = getIssuerFromCredentialOfferPayload(requestPayload);
    if (requestPayload.grants?.[PRE_AUTH_GRANT_LITERAL]) {
      isPinRequired = requestPayload.grants[PRE_AUTH_GRANT_LITERAL]?.user_pin_required ?? false;
    }
    debug(`Pin required for issuer ${issuer}: ${isPinRequired}`);
    return isPinRequired;
  }

  private assertNumericPin(isPinRequired?: boolean, pin?: string): void {
    if (isPinRequired) {
      if (!pin || !/^\d{1,8}$/.test(pin)) {
        debug(`Pin is not 1 to 8 digits long`);
        throw new Error('A valid pin consisting of maximal 8 numeric characters must be present.');
      }
    } else if (pin) {
      debug(`Pin set, whilst not required`);
      throw new Error('Cannot set a pin, when the pin is not required.');
    }
  }

  private assertNonEmptyPreAuthorizedCode(accessTokenRequest: AccessTokenRequest): void {
    if (!accessTokenRequest[PRE_AUTH_CODE_LITERAL]) {
      debug(`No pre-authorized code present, whilst it is required`);
      throw new Error('Pre-authorization must be proven by presenting the pre-authorized code. Code must be present.');
    }
  }

  private assertNonEmptyCodeVerifier(accessTokenRequest: AccessTokenRequest): void {
    if (!accessTokenRequest.code_verifier) {
      debug('No code_verifier present, whilst it is required');
      throw new Error('Authorization flow requires the code_verifier to be present');
    }
  }

  private assertNonEmptyCode(accessTokenRequest: AccessTokenRequest): void {
    if (!accessTokenRequest.code) {
      debug('No code present, whilst it is required');
      throw new Error('Authorization flow requires the code to be present');
    }
  }
  private validate(accessTokenRequest: AccessTokenRequest, isPinRequired?: boolean): void {
    if (accessTokenRequest.grant_type === GrantTypes.PRE_AUTHORIZED_CODE) {
      this.assertPreAuthorizedGrantType(accessTokenRequest.grant_type);
      this.assertNonEmptyPreAuthorizedCode(accessTokenRequest);
      this.assertNumericPin(isPinRequired, accessTokenRequest.user_pin);
    } else if (accessTokenRequest.grant_type === GrantTypes.AUTHORIZATION_CODE) {
      this.assertAuthorizationGrantType(accessTokenRequest.grant_type);
      this.assertNonEmptyCodeVerifier(accessTokenRequest);
      this.assertNonEmptyCode(accessTokenRequest);
    } else {
      this.throwNotSupportedFlow();
    }
  }

  private async sendAuthCode(
    requestTokenURL: string,
    accessTokenRequest: AccessTokenRequest,
    opts?: { headers?: Record<string, string> },
  ): Promise<OpenIDResponse<AccessTokenResponse>> {
    return await formPost(requestTokenURL, convertJsonToURI(accessTokenRequest, { mode: JsonURIMode.X_FORM_WWW_URLENCODED }), {
      customHeaders: opts?.headers ? opts.headers : undefined,
    });
  }

  public static determineTokenURL({
    asOpts,
    issuerOpts,
    metadata,
  }: {
    asOpts?: AuthorizationServerOpts;
    issuerOpts?: IssuerOpts;
    metadata?: EndpointMetadata;
  }): string {
    if (!asOpts && !metadata?.token_endpoint && !issuerOpts) {
      throw new Error('Cannot determine token URL if no issuer, metadata and no Authorization Server values are present');
    }
    let url;
    if (asOpts && asOpts.as) {
      url = this.creatTokenURLFromURL(asOpts.as, asOpts?.allowInsecureEndpoints, asOpts.tokenEndpoint);
    } else if (metadata?.token_endpoint) {
      url = metadata.token_endpoint;
    } else {
      if (!issuerOpts?.issuer) {
        throw Error('Either authorization server options, a token endpoint or issuer options are required at this point');
      }
      url = this.creatTokenURLFromURL(issuerOpts.issuer, asOpts?.allowInsecureEndpoints, issuerOpts.tokenEndpoint);
    }

    if (!url || !ObjectUtils.isString(url)) {
      throw new Error('No authorization server token URL present. Cannot acquire access token');
    }
    debug(`Token endpoint determined to be ${url}`);
    return url;
  }

  private static creatTokenURLFromURL(url: string, allowInsecureEndpoints?: boolean, tokenEndpoint?: string): string {
    if (allowInsecureEndpoints !== true && url.startsWith('http:')) {
      throw Error(
        `Unprotected token endpoints are not allowed ${url}. Use the 'allowInsecureEndpoints' param if you really need this for dev/testing!`,
      );
    }
    const hostname = url.replace(/https?:\/\//, '').replace(/\/$/, '');
    const endpoint = tokenEndpoint ? (tokenEndpoint.startsWith('/') ? tokenEndpoint : tokenEndpoint.substring(1)) : '/token';
    const scheme = url.split('://')[0];
    return `${scheme ? scheme + '://' : 'https://'}${hostname}${endpoint}`;
  }

  private throwNotSupportedFlow(): void {
    debug(`Only pre-authorized or authorization code flows supported.`);
    throw new Error('Only pre-authorized-code or authorization code flows are supported');
  }
}
