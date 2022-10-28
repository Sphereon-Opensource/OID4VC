import { ObjectUtils } from '@sphereon/ssi-types';

import { MetadataClient } from './MetadataClient';
import { convertJsonToURI, formPost } from './functions';
import {
  AccessTokenRequest,
  AccessTokenRequestOpts,
  AccessTokenResponse,
  AuthorizationServerOpts,
  EndpointMetadata,
  ErrorResponse,
  GrantTypes,
  IssuanceInitiationRequestPayload,
  IssuanceInitiationWithBaseUrl,
  IssuerOpts,
  PRE_AUTH_CODE_LITERAL,
} from './types';

export class AccessTokenClient {
  public async acquireAccessTokenUsingIssuanceInitiation(
    issuanceInitiation: IssuanceInitiationWithBaseUrl,
    opts?: AccessTokenRequestOpts
  ): Promise<AccessTokenResponse | ErrorResponse> {
    const { issuanceInitiationRequest } = issuanceInitiation;
    let isPinRequired = false;
    if (issuanceInitiationRequest !== undefined) {
      if (typeof issuanceInitiationRequest.user_pin_required === 'string') {
        isPinRequired = issuanceInitiationRequest.user_pin_required.toLowerCase() === 'true';
      } else if (typeof issuanceInitiationRequest.user_pin_required === 'boolean') {
        isPinRequired = issuanceInitiationRequest.user_pin_required;
      }
    }
    const reqOpts = {
      isPinRequired,
      issuerOpts: { issuer: issuanceInitiationRequest.issuer },
      asOpts: opts?.asOpts ? { ...opts.asOpts } : undefined,
      metadata: opts?.metadata,
    };
    return await this.acquireAccessTokenUsingRequest(await this.createAccessTokenRequest(issuanceInitiationRequest, opts), reqOpts);
  }

  public async acquireAccessTokenUsingRequest(
    accessTokenRequest: AccessTokenRequest,
    opts?: { isPinRequired?: boolean; metadata?: EndpointMetadata; asOpts?: AuthorizationServerOpts; issuerOpts?: IssuerOpts }
  ): Promise<AccessTokenResponse | ErrorResponse> {
    this.validate(accessTokenRequest, opts?.isPinRequired);
    const requestTokenURL = this.determineTokenURL(
      opts?.asOpts,
      opts?.issuerOpts,
      opts?.metadata
        ? opts?.metadata
        : opts?.issuerOpts?.fetchMetadata
        ? await MetadataClient.retrieveAllMetadata(opts?.issuerOpts.issuer, { errorOnNotFound: false })
        : undefined
    );
    return this.sendAuthCode(requestTokenURL, accessTokenRequest);
  }

  public async createAccessTokenRequest(
    issuanceInitiationRequest: IssuanceInitiationRequestPayload,
    opts?: AccessTokenRequestOpts
  ): Promise<AccessTokenRequest> {
    const request: Partial<AccessTokenRequest> = {};
    if (opts?.asOpts?.clientId) {
      opts.asOpts.clientId;
    }
    if (issuanceInitiationRequest.user_pin_required) {
      this.assertNumericPin(true, opts.pin);
      request.user_pin = opts.pin;
    }
    if (issuanceInitiationRequest[PRE_AUTH_CODE_LITERAL]) {
      request.grant_type = GrantTypes.PRE_AUTHORIZED_CODE;
      request[PRE_AUTH_CODE_LITERAL] = issuanceInitiationRequest[PRE_AUTH_CODE_LITERAL];
    }
    if (issuanceInitiationRequest.op_state) {
      if (issuanceInitiationRequest[PRE_AUTH_CODE_LITERAL]) {
        throw new Error('Cannot have both a pre_authorized_code and a op_state in the same initiation request');
      }
      request.grant_type = GrantTypes.AUTHORIZATION_CODE;
      this.throwNotSupportedFlow();
    }

    return request as AccessTokenRequest;
  }

  private assertPreAuthorizedGrantType(grantType: GrantTypes): void {
    if (GrantTypes.PRE_AUTHORIZED_CODE !== grantType) {
      throw new Error("grant type must be 'urn:ietf:params:oauth:grant-type:pre-authorized_code'");
    }
  }

  private assertNumericPin(isPinRequired?: boolean, pin?: string): void {
    if (isPinRequired) {
      if (!pin || !/^\d{1,8}$/.test(pin)) {
        throw new Error('A valid pin consisting of maximal 8 numeric characters must be present.');
      }
    } else if (pin) {
      throw new Error('Cannot set a pin, when the pin is not required.');
    }
  }

  private assertNonEmptyPreAuthorizedCode(accessTokenRequest: AccessTokenRequest): void {
    if (!accessTokenRequest[PRE_AUTH_CODE_LITERAL]) {
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

  private async sendAuthCode(requestTokenURL: string, accessTokenRequest: AccessTokenRequest): Promise<AccessTokenResponse | ErrorResponse> {
    const response = await formPost(requestTokenURL, convertJsonToURI(accessTokenRequest));
    return await response.json();
  }

  private determineTokenURL(asOpts?: AuthorizationServerOpts, issuerOpts?: IssuerOpts, metadata?: EndpointMetadata): string {
    if (!asOpts && !issuerOpts) {
      throw new Error('Cannot determine token URL if no issuer and no Authorization Server values are present');
    }
    const url =
      asOpts && asOpts.as
        ? this.creatTokenURLFromURL(asOpts.as, asOpts.tokenEndpoint)
        : metadata?.token_endpoint
        ? metadata.token_endpoint
        : this.creatTokenURLFromURL(issuerOpts.issuer, issuerOpts.tokenEndpoint);
    if (!url || !ObjectUtils.isString(url)) {
      throw new Error('No authorization server token URL present. Cannot acquire access token');
    }
    return url;
  }

  private creatTokenURLFromURL(url: string, tokenEndpoint?: string): string {
    const hostname = url.replace(/https?:\/\//, '').replace(/\/$/, '');
    const endpoint = tokenEndpoint ? (tokenEndpoint.startsWith('/') ? tokenEndpoint : tokenEndpoint.substring(1)) : '/token';
    // We always require https
    return `https://${hostname}${endpoint}`;
  }

  private throwNotSupportedFlow(): void {
    throw new Error('Only pre-authorized-code flow is supported');
  }
}
