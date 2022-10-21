import { ObjectUtils } from '@sphereon/ssi-types';

import { MetadataClient } from './MetadataClient';
import { convertJsonToURI, formPost } from './functions';
import {
  AccessTokenRequest,
  AccessTokenRequestOpts,
  AccessTokenResponse,
  AuthorizationServerOpts,
  ErrorResponse,
  GrantTypes,
  IssuanceInitiationRequestPayload,
  IssuanceInitiationWithBaseUrl,
  IssuerOpts,
  OID4VCIServerMetadata,
  PRE_AUTH_CODE_LITERAL,
} from './types';

export class AccessTokenClient {
  public async acquireAccessTokenUsingIssuanceInitiation(
    issuanceInitiation: IssuanceInitiationWithBaseUrl,
    opts?: AccessTokenRequestOpts
  ): Promise<AccessTokenResponse | ErrorResponse> {
    const { issuanceInitiationRequest } = issuanceInitiation;
    const reqOpts = {
      isPinRequired: issuanceInitiationRequest.user_pin_required || false,
      issuerOpts: { issuer: issuanceInitiationRequest.issuer },
      asOpts: opts?.asOpts ? { ...opts.asOpts } : undefined,
    };
    return await this.acquireAccessTokenUsingRequest(await this.createAccessTokenRequest(issuanceInitiationRequest, opts), reqOpts);
  }

  public async acquireAccessTokenUsingRequest(
    accessTokenRequest: AccessTokenRequest,
    opts?: { isPinRequired?: boolean; metadata?: OID4VCIServerMetadata; asOpts?: AuthorizationServerOpts; issuerOpts?: IssuerOpts }
  ): Promise<AccessTokenResponse | ErrorResponse> {
    this.validate(accessTokenRequest, opts?.isPinRequired);
    const requestTokenURL = this.determineTokenURL(
      opts?.asOpts,
      opts?.issuerOpts,
      opts?.metadata
        ? opts?.metadata
        : opts?.issuerOpts?.fetchMetadata
        ? await MetadataClient.retrieveOID4VCIServerMetadata(opts?.issuerOpts.issuer)
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
      if (!pin || pin.length === 0 || pin.length > 8 || !/^-?\d+$/.test(pin)) {
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

  private determineTokenURL(asOpts?: AuthorizationServerOpts, issuerOpts?: IssuerOpts, metadata?: OID4VCIServerMetadata): string {
    if (!asOpts && !issuerOpts) {
      throw new Error('Cannot determine token URL if no issuer and no Authorization Server values are present');
    }
    const url = asOpts
      ? this.creatTokenURLFromURL(asOpts.as, asOpts.tokenEndpoint)
      : metadata
      ? metadata.token_endpoint
      : this.creatTokenURLFromURL(issuerOpts.issuer, issuerOpts.tokenEndpoint);
    if (!url || !ObjectUtils.isString(url)) {
      throw new Error('No authorization server token URL present. Cannot acquire access token');
    }
    return url;
  }

  private creatTokenURLFromURL(url: string, tokenEndpoint?: string): string {
    const hostname = url.replace(/https?:\/\//, '').split('/')[0];
    const endpoint = tokenEndpoint ? tokenEndpoint : '/token';
    // We always require https
    return `https://${hostname}${endpoint}`;
  }

  private throwNotSupportedFlow(): void {
    throw new Error('Only pre-authorized-code flow is supported');
  }
}
