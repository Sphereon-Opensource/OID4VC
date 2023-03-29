import {
  CredentialOfferRequestPayloadV11,
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromURI,
  IssuanceInitiationRequestPayloadV9,
  OpenId4VCIVersion,
} from '@sphereon/openid4vci-common';
import Debug from 'debug';

import { convertJsonToURI, convertURIToJsonObject } from './functions';

const debug = Debug('sphereon:openid4vci:initiation');

export class CredentialOffer {
  public static fromURI(uri: string): CredentialOfferRequestWithBaseUrl {
    debug(`issuance initiation URI: ${uri}`);
    if (!uri.includes('?')) {
      debug(`Invalid issuance initiation URI: ${uri}`);
      throw new Error('Invalid Issuance Initiation Request Payload');
    }
    const baseUrl = uri.split('?')[0];
    const version = determineSpecVersionFromURI(uri);
    const issuanceInitiationRequest = convertURIToJsonObject(uri, {
      arrayTypeProperties: ['credential_type'],
      requiredProperties: ['issuer', 'credential_type'],
    });
    const request =
      version < OpenId4VCIVersion.VER_11.valueOf()
        ? (issuanceInitiationRequest as IssuanceInitiationRequestPayloadV9)
        : (issuanceInitiationRequest as CredentialOfferRequestPayloadV11);

    return {
      baseUrl,
      request,
      version,
    };
  }

  public static toURI(issuanceInitiation: CredentialOfferRequestWithBaseUrl): string {
    // todo: Add scheme/version support
    return convertJsonToURI(issuanceInitiation.request, {
      baseUrl: issuanceInitiation.baseUrl,
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type'],
    });
  }
}
