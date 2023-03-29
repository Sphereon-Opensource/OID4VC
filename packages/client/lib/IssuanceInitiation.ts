import { IssuanceInitiationRequestPayload, IssuanceInitiationWithBaseUrl, OpenId4VCIVersion } from '@sphereon/openid4vci-common';
import Debug from 'debug';

import { convertJsonToURI, convertURIToJsonObject } from './functions';

const debug = Debug('sphereon:openid4vci:initiation');

export class IssuanceInitiation {
  public readonly _version: OpenId4VCIVersion;
  private readonly _issuanceInitiationWithBaseUrl: IssuanceInitiationWithBaseUrl;

  private constructor(issuanceInitiationWithBaseUrl: IssuanceInitiationWithBaseUrl) {
    this._version = OpenId4VCIVersion.VER_9;
    this._issuanceInitiationWithBaseUrl = issuanceInitiationWithBaseUrl;
  }

  public static fromURI(issuanceInitiationURI: string): IssuanceInitiationWithBaseUrl {
    debug(`issuance initiation URI: ${issuanceInitiationURI}`);
    if (!issuanceInitiationURI.includes('?')) {
      debug(`Invalid issuance initiation URI: ${issuanceInitiationURI}`);
      throw new Error('Invalid Issuance Initiation Request Payload');
    }
    const baseUrl = issuanceInitiationURI.split('?')[0];
    const issuanceInitiationRequest = convertURIToJsonObject(issuanceInitiationURI, {
      arrayTypeProperties: ['credential_type'],
      requiredProperties: ['issuer', 'credential_type'],
    }) as IssuanceInitiationRequestPayload;

    return {
      baseUrl,
      issuanceInitiationRequest,
    };
  }

  public static toURI(issuanceInitiationWithBaseUrl: IssuanceInitiationWithBaseUrl): string {
    const credentialOfferPayload = issuanceInitiationWithBaseUrl.issuanceInitiationRequest;
    return convertJsonToURI(credentialOfferPayload, {
      baseUrl: issuanceInitiationWithBaseUrl.baseUrl,
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type'],
    });
  }

  public getCredentialTypes(): string[] {
    const issuanceInitiationRequest = this._issuanceInitiationWithBaseUrl.issuanceInitiationRequest;
    return typeof issuanceInitiationRequest.credential_type === 'string'
      ? [issuanceInitiationRequest.credential_type]
      : issuanceInitiationRequest.credential_type;
  }

  public getIssuer(): string {
    return this._issuanceInitiationWithBaseUrl.issuanceInitiationRequest.issuer;
  }

  public assertIssuerData(): void {
    if (!this._issuanceInitiationWithBaseUrl) {
      throw Error(`No issuance initiation present`);
    }
  }

  get issuanceInitiationWithBaseUrl() {
    return this._issuanceInitiationWithBaseUrl;
  }

  get version() {
    return this._version;
  }
}
