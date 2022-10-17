import { convertJsonToURI, convertURIToJsonObject } from './functions';
import { IssuanceInitiationRequestPayload, IssuanceInitiationWithBaseUrl } from './types';

export class IssuanceInitiation {
  public static fromURI(issuanceInitiationURI: string): IssuanceInitiationWithBaseUrl {
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

  public static toURI(issuanceInitiation: IssuanceInitiationWithBaseUrl): string {
    return convertJsonToURI(issuanceInitiation.issuanceInitiationRequest, {
      baseUrl: issuanceInitiation.baseUrl,
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type'],
    });
  }
}
