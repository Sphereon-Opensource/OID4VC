import { AuthorizationRequest } from '../authorization-request';
import { AuthorizationResponse } from '../authorization-response';

export interface AuthorizationRequestState {
  correlationId?: string;
  request: AuthorizationRequest;
  status: AuthorizationRequestStateStatus;
  timestamp: number;
  lastUpdated: number;
  error?: Error;
}

export interface AuthorizationResponseState {
  correlationId?: string;
  response: AuthorizationResponse;
  status: AuthorizationResponseStateStatus;
  timestamp: number;
  lastUpdated: number;
  error?: Error;
}

export enum AuthorizationRequestStateStatus {
  CREATED = 'created',
  SENT = 'sent',
  RECEIVED = 'received',
  VERIFIED = 'verified',
  ERROR = 'error',
}

export enum AuthorizationResponseStateStatus {
  CREATED = 'created',
  SENT = 'sent',
  RECEIVED = 'received',
  VERIFIED = 'verified',
  ERROR = 'error',
}
