import {
  AccessTokenRequest,
  AccessTokenRequestOpts,
  AccessTokenResponse,
  AuthorizationServerOpts,
  CredentialOfferPayload,
  CredentialOfferPayloadV1_0_11,
  CredentialOfferV1_0_09,
  EndpointMetadata,
  getIssuerFromCredentialOfferPayload,
  GrantTypes,
  isCredentialOfferV1_0_09,
  isCredentialOfferV1_0_11,
  IssuerOpts,
  OpenIDResponse,
  PRE_AUTH_CODE_LITERAL,
  TokenErrorResponse,
} from '@sphereon/openid4vci-common';
import { ObjectUtils } from '@sphereon/ssi-types';
import Debug from 'debug';

import { MetadataClient } from './MetadataClient';
import { convertJsonToURI, formPost } from './functions';

const debug = Debug('sphereon:openid4vci:token');

export class AccessTokenClient {
  public async acquireAccessToken({
    credentialOffer,
    asOpts,
    pin,
    codeVerifier,
    code,
    redirectUri,
    metadata,
  }: AccessTokenRequestOpts): Promise<OpenIDResponse<AccessTokenResponse>> {
    const { request } = credentialOffer;

    const isPinRequired = this.isPinRequiredValue(request);
    const issuerOpts = { issuer: getIssuerFromCredentialOfferPayload(request) };

    return await this.acquireAccessTokenUsingRequest({
      accessTokenRequest: await this.createAccessTokenRequest({
        credentialOffer,
        asOpts,
        codeVerifier,
        code,
        redirectUri,
        pin,
      }),
      isPinRequired,
      metadata,
      asOpts,
      issuerOpts,
    });
  }

  public async acquireAccessTokenUsingRequest({
    accessTokenRequest,
    isPinRequired,
    metadata,
    asOpts,
    issuerOpts,
  }: {
    accessTokenRequest: AccessTokenRequest;
    isPinRequired?: boolean;
    metadata?: EndpointMetadata;
    asOpts?: AuthorizationServerOpts;
    issuerOpts?: IssuerOpts;
  }): Promise<OpenIDResponse<AccessTokenResponse>> {
    this.validate(accessTokenRequest, isPinRequired);
    const requestTokenURL = AccessTokenClient.determineTokenURL({
      asOpts,
      issuerOpts,
      metadata: metadata
        ? metadata
        : issuerOpts?.fetchMetadata
        ? await MetadataClient.retrieveAllMetadata(issuerOpts.issuer, { errorOnNotFound: false })
        : undefined,
    });
    return this.sendAuthCode(requestTokenURL, accessTokenRequest);
  }

  public async createAccessTokenRequest({
    credentialOffer,
    asOpts,
    pin,
    codeVerifier,
    code,
    redirectUri,
  }: AccessTokenRequestOpts): Promise<AccessTokenRequest> {
    const credentialOfferRequest = credentialOffer.request;
    const request: Partial<AccessTokenRequest> = {};
    if (asOpts?.clientId) {
      request.client_id = asOpts.clientId;
    }

    this.assertNumericPin(this.isPinRequiredValue(credentialOfferRequest), pin);
    request.user_pin = pin;

    if (credentialOfferRequest[PRE_AUTH_CODE_LITERAL as keyof CredentialOfferPayload]) {
      if (codeVerifier) {
        throw new Error('Cannot pass a code_verifier when flow type is pre-authorized');
      }
      request.grant_type = GrantTypes.PRE_AUTHORIZED_CODE;
      //todo: handle this for v11
      request[PRE_AUTH_CODE_LITERAL] = (credentialOfferRequest as CredentialOfferV1_0_09)[PRE_AUTH_CODE_LITERAL];
    }
    if ('op_state' in credentialOfferRequest || 'issuer_state' in credentialOfferRequest) {
      this.throwNotSupportedFlow();
      request.grant_type = GrantTypes.AUTHORIZATION_CODE;
    }
    if (codeVerifier) {
      request.code_verifier = codeVerifier;
      request.code = code;
      request.redirect_uri = redirectUri;
      request.grant_type = GrantTypes.AUTHORIZATION_CODE;
    }
    //todo: handle this for v11
    if (request.grant_type === GrantTypes.AUTHORIZATION_CODE && (credentialOfferRequest as CredentialOfferV1_0_09)[PRE_AUTH_CODE_LITERAL]) {
      throw Error('A pre_authorized_code flow cannot have an op_state in the initiation request');
    }

    return request as AccessTokenRequest;
  }

  private assertPreAuthorizedGrantType(grantType: GrantTypes): void {
    if (GrantTypes.PRE_AUTHORIZED_CODE !== grantType) {
      throw new Error("grant type must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code'");
    }
  }

  private assertAuthorizationGrantType(grantType: GrantTypes): void {
    if (GrantTypes.AUTHORIZATION_CODE !== grantType) {
      throw new Error("grant type must be 'authorization_code'");
    }
  }

  private isPinRequiredValue(requestPayload: CredentialOfferPayload): boolean {
    let isPinRequired = false;
    if (!requestPayload) {
      throw new Error(TokenErrorResponse.invalid_request);
    }
    const issuer = getIssuerFromCredentialOfferPayload(requestPayload);
    if (isCredentialOfferV1_0_09(requestPayload)) {
      requestPayload = requestPayload as CredentialOfferV1_0_09;
      if (typeof requestPayload.user_pin_required === 'string') {
        isPinRequired = requestPayload.user_pin_required.toLowerCase() === 'true';
      } else if (typeof requestPayload.user_pin_required === 'boolean') {
        isPinRequired = requestPayload.user_pin_required;
      }
    } else if (isCredentialOfferV1_0_11(requestPayload)) {
      requestPayload = requestPayload as CredentialOfferPayloadV1_0_11;
      if ('grants' in requestPayload && 'urn:ietf:params:oauth:grant-type:pre-authorized_code' in requestPayload.grants!) {
        isPinRequired = requestPayload!.grants!['urn:ietf:params:oauth:grant-type:pre-authorized_code']!.user_pin_required;
      }
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

  private assertNonEmptyRedirectUri(accessTokenRequest: AccessTokenRequest): void {
    if (!accessTokenRequest.redirect_uri) {
      debug('No redirect_uri present, whilst it is required');
      throw new Error('Authorization flow requires the redirect_uri to be present');
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
      this.assertNonEmptyRedirectUri(accessTokenRequest);
    } else {
      this.throwNotSupportedFlow;
    }
  }

  private async sendAuthCode(requestTokenURL: string, accessTokenRequest: AccessTokenRequest): Promise<OpenIDResponse<AccessTokenResponse>> {
    return await formPost(requestTokenURL, convertJsonToURI(accessTokenRequest));
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
      if (!issuerOpts) {
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
    if (allowInsecureEndpoints !== true && url.startsWith('http://')) {
      throw Error(`Unprotected token endpoints are not allowed ${url}`);
    }
    const hostname = url.replace(/https?:\/\//, '').replace(/\/$/, '');
    const endpoint = tokenEndpoint ? (tokenEndpoint.startsWith('/') ? tokenEndpoint : tokenEndpoint.substring(1)) : '/token';
    // We always require https
    return `https://${hostname}${endpoint}`;
  }

  private throwNotSupportedFlow(): void {
    debug(`Only pre-authorized flow supported.`);
    throw new Error('Only pre-authorized-code flow is supported');
  }
}
