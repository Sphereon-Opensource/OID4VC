import {
  CredentialOfferRequestPayloadV11,
  CredentialOfferRequestWithBaseUrl,
  IssuanceInitiationRequestPayloadV9,
  OpenId4VCIVersion,
} from '@sphereon/openid4vci-common';
import Debug from 'debug';

import { convertJsonToURI, convertURIToJsonObject, determineSpecVersionFromURI } from './functions';

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
    }) as IssuanceInitiationRequestPayloadV9;

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

  public static toURI(uri: CredentialOfferRequestWithBaseUrl): string {
    const request = uri.request;
    return convertJsonToURI(request, {
      baseUrl: uri.baseUrl,
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type'],
    });
  }
}
