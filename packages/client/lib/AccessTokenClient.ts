import { ObjectUtils } from '@sphereon/ssi-types';
import Debug from 'debug';

import { MetadataClient } from './MetadataClient';
import { convertJsonToURI, formPost } from './functions';
import {
  AccessTokenRequest,
  AccessTokenRequestOpts,
  AccessTokenResponse,
  AuthorizationServerOpts,
  EndpointMetadata,
  GrantTypes,
  IssuanceInitiationRequestPayload,
  IssuerOpts,
  OpenIDResponse,
  PRE_AUTH_CODE_LITERAL,
} from './types';

const debug = Debug('sphereon:openid4vci:token');

export class AccessTokenClient {
  public async acquireAccessTokenUsingIssuanceInitiation({
    issuanceInitiation,
    asOpts,
    pin,
    metadata,
  }: AccessTokenRequestOpts): Promise<OpenIDResponse<AccessTokenResponse>> {
    const { issuanceInitiationRequest } = issuanceInitiation;

    const isPinRequired = this.isPinRequiredValue(issuanceInitiationRequest);
    const issuerOpts = { issuer: issuanceInitiationRequest.issuer };

    return await this.acquireAccessTokenUsingRequest({
      accessTokenRequest: await this.createAccessTokenRequest({
        issuanceInitiation,
        asOpts,
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

  public async createAccessTokenRequest({ issuanceInitiation, asOpts, pin }: AccessTokenRequestOpts): Promise<AccessTokenRequest> {
    const issuanceInitiationRequest = issuanceInitiation.issuanceInitiationRequest;
    const request: Partial<AccessTokenRequest> = {};
    if (asOpts?.clientId) {
      request.client_id = asOpts.clientId;
    }

    this.assertNumericPin(this.isPinRequiredValue(issuanceInitiationRequest), pin);
    request.user_pin = pin;

    if (issuanceInitiationRequest[PRE_AUTH_CODE_LITERAL]) {
      request.grant_type = GrantTypes.PRE_AUTHORIZED_CODE;
      request[PRE_AUTH_CODE_LITERAL] = issuanceInitiationRequest[PRE_AUTH_CODE_LITERAL];
    }
    if (issuanceInitiationRequest.op_state) {
      this.throwNotSupportedFlow();
      /**
       * Code is here for when we start to support this flow
       */
      // if (issuanceInitiationRequest[PRE_AUTH_CODE_LITERAL]) {
      //   throw new Error('Cannot have both a pre_authorized_code and a op_state in the same initiation request');
      // }
      // request.grant_type = GrantTypes.AUTHORIZATION_CODE;
    }

    return request as AccessTokenRequest;
  }

  private assertPreAuthorizedGrantType(grantType: GrantTypes): void {
    if (GrantTypes.PRE_AUTHORIZED_CODE !== grantType) {
      throw new Error("grant type must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code'");
    }
  }

  private isPinRequiredValue(issuanceInitiationRequest: IssuanceInitiationRequestPayload): boolean {
    let isPinRequired = false;
    if (issuanceInitiationRequest !== undefined) {
      if (typeof issuanceInitiationRequest.user_pin_required === 'string') {
        isPinRequired = issuanceInitiationRequest.user_pin_required.toLowerCase() === 'true';
      } else if (typeof issuanceInitiationRequest.user_pin_required === 'boolean') {
        isPinRequired = issuanceInitiationRequest.user_pin_required;
      }
    }
    debug(`Pin required for issuer ${issuanceInitiationRequest.issuer}: ${isPinRequired}`);
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

  private validate(accessTokenRequest: AccessTokenRequest, isPinRequired?: boolean): void {
    if (accessTokenRequest.grant_type === GrantTypes.PRE_AUTHORIZED_CODE) {
      this.assertPreAuthorizedGrantType(accessTokenRequest.grant_type);
      this.assertNonEmptyPreAuthorizedCode(accessTokenRequest);
      this.assertNumericPin(isPinRequired, accessTokenRequest.user_pin);
    } else {
      this.throwNotSupportedFlow();
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
    const url =
      asOpts && asOpts.as
        ? this.creatTokenURLFromURL(asOpts.as, asOpts?.allowInsecureEndpoints, asOpts.tokenEndpoint)
        : metadata?.token_endpoint
        ? metadata.token_endpoint
        : this.creatTokenURLFromURL(issuerOpts.issuer, asOpts?.allowInsecureEndpoints, issuerOpts.tokenEndpoint);
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
