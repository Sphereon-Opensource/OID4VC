import { IssuanceInitiationRequestParams } from './IssuanceInitiationRequestTypes';

export enum Flow {
  AUTHORIZATION_CODE_FLOW = 'Authorization Code Flow',
  PRE_AUTHORIZED_CODE_FLOW = 'Pre-Authorized Code Flow',
}

export module Flow {
  export function valueOf(request: IssuanceInitiationRequestParams) {
    if (request.pre_authorized_code) {
      return Flow.PRE_AUTHORIZED_CODE_FLOW;
    }
    return Flow.AUTHORIZATION_CODE_FLOW;
  }
}
