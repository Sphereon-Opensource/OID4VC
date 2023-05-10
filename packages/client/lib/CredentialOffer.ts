import {
  CredentialOfferPayload,
  CredentialOfferPayloadV1_0_09,
  CredentialOfferPayloadV1_0_11,
  CredentialOfferRequestWithBaseUrl,
  OpenId4VCIVersion,
} from '@sphereon/oid4vci-common';
import { determineSpecVersionFromURI } from '@sphereon/oid4vci-common';
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
    const issuanceInitiationRequest: CredentialOfferPayload =
      version < OpenId4VCIVersion.VER_1_0_11
        ? (convertURIToJsonObject(uri, {
            arrayTypeProperties: ['credential_type'],
            requiredProperties: ['issuer', 'credential_type'],
          }) as CredentialOfferPayloadV1_0_09)
        : (convertURIToJsonObject(uri, {
            arrayTypeProperties: ['credentials'],
            requiredProperties: ['credentials', 'credential_issuer'],
          }) as CredentialOfferPayloadV1_0_11);

    const request =
      version < OpenId4VCIVersion.VER_1_0_11.valueOf()
        ? (issuanceInitiationRequest as CredentialOfferPayloadV1_0_09)
        : (issuanceInitiationRequest as CredentialOfferPayloadV1_0_11);

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
