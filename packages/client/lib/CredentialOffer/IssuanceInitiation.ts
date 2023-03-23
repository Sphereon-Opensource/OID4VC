import {
  EndpointMetadata,
  IssuanceInitiationRequestPayload,
  IssuanceInitiationWithBaseUrl,
  OpenId4VCIVersion
} from '@sphereon/openid4vci-common';
import Debug from 'debug';

import {MetadataClient} from "../MetadataClient";
import { convertJsonToURI, convertURIToJsonObject } from '../functions';

import {CredentialOfferClient} from "./index";

const debug = Debug('sphereon:openid4vci:initiation');

export class IssuanceInitiation implements CredentialOfferClient {
  public static readonly version: OpenId4VCIVersion.VER_9;

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

  /**
   * Retrieve metadata using the Initiation obtained from a previous step
   *
   * @param initiation
   */
  public static async getServerMetaDataFromInitiation(initiation: IssuanceInitiationWithBaseUrl): Promise<EndpointMetadata> {
    return this.getServerFromInitiationRequest(initiation.issuanceInitiationRequest);
  }

  /**
   * Retrieve the metadata using the initiation request obtained from a previous step
   * @param initiationRequest
   */
  public static async getServerFromInitiationRequest(initiationRequest: IssuanceInitiationRequestPayload): Promise<EndpointMetadata> {
    return this.getServerMetaData(initiationRequest.issuer);
  }


  public static async getServerMetaData(issuer: string, opts?: { errorOnNotFound: boolean }): Promise<EndpointMetadata> {
    return await MetadataClient.retrieveAllMetadata(issuer, opts);
  }

  public static getCredentialTypes(issuanceInitiationRequestPayload: IssuanceInitiationRequestPayload): string[] {
    return typeof issuanceInitiationRequestPayload.credential_type === 'string'
        ? [issuanceInitiationRequestPayload.credential_type]
        : issuanceInitiationRequestPayload.credential_type;
  }

  public static getIssuer(initiation: IssuanceInitiationWithBaseUrl): string {
    return initiation.issuanceInitiationRequest.issuer;
  }

  public static assertIssuerData(initiation: IssuanceInitiationWithBaseUrl): void {
    if (!initiation) {
      throw Error(`No issuance initiation present`);
    }
  }

}
