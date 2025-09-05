import { AuthorizationRequest } from '../authorization-request'
import { AuthorizationResponse } from '../authorization-response'
import {CallbackOpts} from './SIOP.types';

export interface AuthorizationRequestState {
  correlationId: string
  queryId: string
  request: AuthorizationRequest
  status: AuthorizationRequestStateStatus
  callback?: CallbackOpts
  timestamp: number
  lastUpdated: number
  error?: Error
}

export interface AuthorizationResponseState {
  correlationId: string
  queryId: string
  response: AuthorizationResponse
  status: AuthorizationResponseStateStatus
  callback?: CallbackOpts
  timestamp: number
  lastUpdated: number
  error?: Error
}

export enum AuthorizationRequestStateStatus {
  CREATED = "authorization_request_created",
  RETRIEVED = "authorization_request_retrieved",
  ERROR = "error"
}

export enum AuthorizationResponseStateStatus {
  RECEIVED = "authorization_response_received",
  VERIFIED = "authorization_response_verified",
  ERROR = "error"
}
