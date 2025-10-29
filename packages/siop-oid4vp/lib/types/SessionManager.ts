import { AuthorizationRequest } from '../authorization-request'
import { AuthorizationResponse } from '../authorization-response'
import {CallbackOpts, VerifiedData} from '../types'

export interface AuthorizationRequestState {
  correlationId: string
  queryId: string
  request: AuthorizationRequest
  status: AuthorizationRequestStateStatus
  callback?: CallbackOpts
  responseRedirectURI?: string
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

export interface AuthorizationResponseStateWithVerifiedData extends AuthorizationResponseState {
  verifiedData?: VerifiedData
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
