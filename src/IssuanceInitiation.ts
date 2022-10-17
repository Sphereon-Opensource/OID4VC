import { convertJsonToURI, convertURIToJsonObject } from './functions';
import { IssuanceInitiationRequestPayload, IssuanceInitiationWithBaseUrl } from './types';

export default class IssuanceInitiation {
  static fromURI(issuanceInitiationURI: string): IssuanceInitiationWithBaseUrl {
    if (!issuanceInitiationURI.includes('?')) {
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

  static toURI(issuanceInitiation: IssuanceInitiationWithBaseUrl): string {
    return convertJsonToURI(issuanceInitiation.issuanceInitiationRequest, {
      baseUrl: issuanceInitiation.baseUrl,
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type'],
    });
  }
}
