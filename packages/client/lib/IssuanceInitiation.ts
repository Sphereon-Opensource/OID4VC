import Debug from 'debug';

import { convertJsonToURI, convertURIToJsonObject } from './functions';
import { IssuanceInitiationRequestPayload, IssuanceInitiationWithBaseUrl } from '@sphereon/openid4vci-common/lib';

const debug = Debug('sphereon:openid4vci:initiation');
export class IssuanceInitiation {
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

  public static toURI(issuanceInitiation: IssuanceInitiationWithBaseUrl): string {
    return convertJsonToURI(issuanceInitiation.issuanceInitiationRequest, {
      baseUrl: issuanceInitiation.baseUrl,
      arrayTypeProperties: ['credential_type'],
      uriTypeProperties: ['issuer', 'credential_type'],
    });
  }
}
