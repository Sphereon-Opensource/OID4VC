import {
  EndpointMetadata,
  IssuanceInitiationRequestPayload,
  IssuanceInitiationWithBaseUrl,
  OIDCVCIVersion
} from '@sphereon/openid4vci-common';
import Debug from 'debug';

import { convertJsonToURI, convertURIToJsonObject } from '../functions';
import {CredentialOfferStrategy} from "./index";
import {MetadataClient} from "../MetadataClient";

const debug = Debug('sphereon:openid4vci:initiation');
export class IssuanceInitiation implements CredentialOfferStrategy {
  readonly version: OIDCVCIVersion;
  private readonly _issuanceInitiationWithBaseUrl: IssuanceInitiationWithBaseUrl;

  public constructor(issuanceInitiationURI: string){
    this.version = OIDCVCIVersion.VER_9;
    this._issuanceInitiationWithBaseUrl = this.fromURI(issuanceInitiationURI);
  }

  public getPayload() : IssuanceInitiationWithBaseUrl {
    return this._issuanceInitiationWithBaseUrl;
  }

  private fromURI(issuanceInitiationURI: string): IssuanceInitiationWithBaseUrl {
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

  public toURI(): string {
    let credentialOfferPayload = this._issuanceInitiationWithBaseUrl.issuanceInitiationRequest;
    return convertJsonToURI(credentialOfferPayload, {
      baseUrl: this._issuanceInitiationWithBaseUrl.baseUrl,
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type'],
    });
  }

  public async getServerMetaData(): Promise<EndpointMetadata> {
    const {issuer} = this._issuanceInitiationWithBaseUrl.issuanceInitiationRequest;
    return await MetadataClient.retrieveAllMetadata(issuer);
  }

  public getCredentialTypes(): string[] {
    let credentialOfferPayload = this._issuanceInitiationWithBaseUrl.issuanceInitiationRequest;
    return typeof credentialOfferPayload.credential_type === 'string'
        ? [credentialOfferPayload.credential_type]
        : credentialOfferPayload.credential_type;
  }

  public getIssuer(): string {
    return this._issuanceInitiationWithBaseUrl.issuanceInitiationRequest.issuer;
  }

  public assertIssuerData(): void {
    if (!this._issuanceInitiationWithBaseUrl) {
      throw Error(`No issuance initiation present`);
    }
  }

  get issuanceInitiationWithBaseUrl(): IssuanceInitiationWithBaseUrl {
    return this._issuanceInitiationWithBaseUrl;
  }
}
