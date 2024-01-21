import { AuthorizationRequestState, AuthorizationResponseState } from '../types';

export interface IRPSessionManager {
  getRequestStateByCorrelationId(correlationId: string, errorOnNotFound?: boolean): Promise<AuthorizationRequestState | undefined>;

  getRequestStateByNonce(nonce: string, errorOnNotFound?: boolean): Promise<AuthorizationRequestState | undefined>;

  getRequestStateByState(state: string, errorOnNotFound?: boolean): Promise<AuthorizationRequestState | undefined>;

  getResponseStateByCorrelationId(correlationId: string, errorOnNotFound?: boolean): Promise<AuthorizationResponseState | undefined>;

  getResponseStateByNonce(nonce: string, errorOnNotFound?: boolean): Promise<AuthorizationResponseState | undefined>;

  getResponseStateByState(state: string, errorOnNotFound?: boolean): Promise<AuthorizationResponseState | undefined>;

  getCorrelationIdByNonce(nonce: string, errorOnNotFound?: boolean): Promise<string | undefined>;

  getCorrelationIdByState(state: string, errorOnNotFound?: boolean): Promise<string | undefined>;

  deleteStateForCorrelationId(correlationId: string);
}
