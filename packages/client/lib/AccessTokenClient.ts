import {
  AccessTokenRequest,
  AccessTokenRequestOpts,
  AccessTokenResponse,
  assertedUniformCredentialOffer,
  AuthorizationServerOpts,
  EndpointMetadata,
  getIssuerFromCredentialOfferPayload,
  GrantTypes,
  isPreAuthCode,
  IssuerOpts,
  OpenIDResponse,
  PRE_AUTH_CODE_LITERAL,
  TokenErrorResponse,
  toUniformCredentialOfferRequest,
  UniformCredentialOfferPayload,
} from '@sphereon/oid4vci-common';
import { ObjectUtils } from '@sphereon/ssi-types';
import Debug from 'debug';

import { MetadataClient } from './MetadataClient';
import { convertJsonToURI, formPost } from './functions';

const debug = Debug('sphereon:oid4vci:token');

export class AccessTokenClient {
  public async acquireAccessToken(opts: AccessTokenRequestOpts): Promise<OpenIDResponse<AccessTokenResponse>> {
    const { asOpts, pin, codeVerifier, code, redirectUri, metadata } = opts;

    const credentialOffer = await assertedUniformCredentialOffer(opts.credentialOffer);
    const isPinRequired = this.isPinRequiredValue(credentialOffer.credential_offer);
    const issuerOpts = {
      issuer: getIssuerFromCredentialOfferPayload(credentialOffer.credential_offer) ?? (metadata?.issuer as string),
    };

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

  public async createAccessTokenRequest(opts: AccessTokenRequestOpts): Promise<AccessTokenRequest> {
    const { asOpts, pin, codeVerifier, code, redirectUri } = opts;
    const credentialOfferRequest = await toUniformCredentialOfferRequest(opts.credentialOffer);
    const request: Partial<AccessTokenRequest> = {};
    if (asOpts?.clientId) {
      request.client_id = asOpts.clientId;
    }

    this.assertNumericPin(this.isPinRequiredValue(credentialOfferRequest.credential_offer), pin);
    request.user_pin = pin;

    const isPreAuth = isPreAuthCode(credentialOfferRequest);
    if (isPreAuth) {
      if (codeVerifier) {
        throw new Error('Cannot pass a code_verifier when flow type is pre-authorized');
      }
      request.grant_type = GrantTypes.PRE_AUTHORIZED_CODE;
      // we actually know it is there because of the isPreAuthCode call
      request[PRE_AUTH_CODE_LITERAL] =
        credentialOfferRequest?.credential_offer.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.[PRE_AUTH_CODE_LITERAL];
    }
    if (credentialOfferRequest.credential_offer.grants?.authorization_code?.issuer_state) {
      this.throwNotSupportedFlow(); // not supported yet
      request.grant_type = GrantTypes.AUTHORIZATION_CODE;
    }
    if (codeVerifier) {
      request.code_verifier = codeVerifier;
      request.code = code;
      request.redirect_uri = redirectUri;
      request.grant_type = GrantTypes.AUTHORIZATION_CODE;
    }
    if (request.grant_type === GrantTypes.AUTHORIZATION_CODE && isPreAuth) {
      throw Error('A pre_authorized_code flow cannot have an issuer state in the credential offer');
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

  private isPinRequiredValue(requestPayload: UniformCredentialOfferPayload): boolean {
    let isPinRequired = false;
    if (!requestPayload) {
      throw new Error(TokenErrorResponse.invalid_request);
    }
    const issuer = getIssuerFromCredentialOfferPayload(requestPayload);
    if (requestPayload.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code']) {
      isPinRequired = requestPayload.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']?.user_pin_required ?? false;
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
      throw Error(`Unprotected token endpoints are not allowed ${url}. Adjust settings if you really need this (dev/test settings only!!)`);
    }
    const hostname = url.replace(/https?:\/\//, '').replace(/\/$/, '');
    const endpoint = tokenEndpoint ? (tokenEndpoint.startsWith('/') ? tokenEndpoint : tokenEndpoint.substring(1)) : '/token';
    const scheme = url.split('://')[0];
    return `${scheme ? scheme + '://' : 'https://'}${hostname}${endpoint}`;
  }

  private throwNotSupportedFlow(): void {
    debug(`Only pre-authorized flow supported.`);
    throw new Error('Only pre-authorized-code flow is supported');
  }
}
