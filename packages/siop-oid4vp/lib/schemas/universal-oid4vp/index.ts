import {
  AuthorizationRequestStateStatus,
  AuthorizationResponseStateStatus,
  CallbackOpts,
  CallbackOptsPayload,
  CreateAuthorizationRequest,
  CreateAuthorizationRequestPayload,
  CreateAuthorizationResponse,
  CreateAuthorizationResponsePayload,
  QRCodeOpts,
  QRCodeOptsPayload,
  RequestUriMethod,
  ResponseMode,
  ResponseType,
  VerifiedDataMode
} from '../../types'
import { z } from 'zod'

export const AuthorizationStatusSchema = z.enum([
  ...Object.values(AuthorizationRequestStateStatus),
  ...Object.values(AuthorizationResponseStateStatus)
])

export const VerifiedDataModeSchema = z.enum(Object.values(VerifiedDataMode))

export const VerifiedDataOptsSchema = z.object({
  modes: z.array(VerifiedDataModeSchema).optional()
})

export const ResponseTypeSchema = z.enum([ResponseType.VP_TOKEN])

export const ResponseModeSchema = z.enum([ResponseMode.DIRECT_POST, ResponseMode.DIRECT_POST_JWT])

export const RequestUriMethodSchema = z.enum(Object.values(RequestUriMethod))

// Internal schemas
export const QRCodeOptsSchema = z.object({
  size: z.number().optional(),
  colorDark: z.string().optional(),
  colorLight: z.string().optional()
})

export const CallbackOptsSchema = z.object({
  url: z.string(),
  verifiedData: VerifiedDataOptsSchema.optional(),
  status: z.array(AuthorizationStatusSchema).optional()
})

export const CreateAuthorizationRequestSchema = z.object({
  queryId: z.string(),
  clientId: z.string().optional(),
  requestUriBase: z.string().optional(),
  correlationId: z.string().optional(),
  requestUriMethod: RequestUriMethodSchema.optional(),
  responseType: ResponseTypeSchema.optional(),
  responseMode: ResponseModeSchema.optional(),
  transactionData: z.array(z.string()).optional(),
  qrCode: QRCodeOptsSchema.optional(),
  directPostResponseRedirectUri: z.string().optional(),
  callback: CallbackOptsSchema.optional()
})

export const CreateAuthorizationResponseSchema = z.object({
  correlationId: z.string(),
  queryId: z.string(),
  requestUri: z.string(),
  statusUri: z.string(),
  qrUri: z.string().optional()
})

// Payload schemas
export const QRCodeOptsPayloadSchema = z.object({
  size: z.number().optional(),
  color_dark: z.string().optional(),
  color_light: z.string().optional()
})

export const CallbackOptsPayloadSchema = z.object({
  url: z.string(),
  verified_data: VerifiedDataOptsSchema.optional(),
  status: z.array(AuthorizationStatusSchema).optional()
})

export const CreateAuthorizationRequestPayloadSchema = z.object({
  query_id: z.string(),
  client_id: z.string().optional(),
  request_uri_base: z.string().optional(),
  correlation_id: z.string().optional(),
  request_uri_method: RequestUriMethodSchema.optional(),
  response_type: ResponseTypeSchema.optional(),
  response_mode: ResponseModeSchema.optional(),
  transaction_data: z.array(z.string()).optional(),
  qr_code: QRCodeOptsPayloadSchema.optional(),
  direct_post_response_redirect_uri: z.string().optional(),
  callback: CallbackOptsPayloadSchema.optional()
})

export const CreateAuthorizationResponsePayloadSchema = z.object({
  correlation_id: z.string(),
  query_id: z.string(),
  request_uri: z.string(),
  status_uri: z.string(),
  qr_uri: z.string().optional()
})


export const qrCodeOptsFromPayload = (payload: QRCodeOptsPayload): QRCodeOpts => {
  const parsed = QRCodeOptsPayloadSchema.parse(payload)
  return {
    size: parsed.size,
    colorDark: parsed.color_dark,
    colorLight: parsed.color_light
  }
}

export const qrCodeOptsToPayload = (internal: QRCodeOpts): QRCodeOptsPayload => {
  const parsed = QRCodeOptsSchema.parse(internal)
  return {
    size: parsed.size,
    color_dark: parsed.colorDark,
    color_light: parsed.colorLight
  }
}

export const callbackOptsFromPayload = (payload: CallbackOptsPayload): CallbackOpts => {
  const parsed = CallbackOptsPayloadSchema.parse(payload)
  return {
    url: parsed.url,
    verifiedData: parsed.verified_data,
    status: parsed.status
  }
}

export const callbackOptsToPayload = (internal: CallbackOpts): CallbackOptsPayload => {
  const parsed = CallbackOptsSchema.parse(internal)
  return {
    url: parsed.url,
    verified_data: parsed.verifiedData,
    status: parsed.status
  }
}

export const createAuthorizationRequestFromPayload = (payload: CreateAuthorizationRequestPayload): CreateAuthorizationRequest => {
  const parsed = CreateAuthorizationRequestPayloadSchema.parse(payload)
  return {
    queryId: parsed.query_id,
    clientId: parsed.client_id,
    requestUriBase: parsed.request_uri_base,
    correlationId: parsed.correlation_id,
    requestUriMethod: parsed.request_uri_method,
    responseType: parsed.response_type,
    responseMode: parsed.response_mode,
    transactionData: parsed.transaction_data,
    qrCode: parsed.qr_code ? qrCodeOptsFromPayload(parsed.qr_code) : undefined,
    directPostResponseRedirectUri: parsed.direct_post_response_redirect_uri,
    callback: parsed.callback ? callbackOptsFromPayload(parsed.callback) : undefined
  }
}

export const createAuthorizationRequestToPayload = (internal: CreateAuthorizationRequest): CreateAuthorizationRequestPayload => {
  const parsed = CreateAuthorizationRequestSchema.parse(internal)
  return {
    query_id: parsed.queryId,
    client_id: parsed.clientId,
    request_uri_base: parsed.requestUriBase,
    correlation_id: parsed.correlationId,
    request_uri_method: parsed.requestUriMethod,
    response_type: parsed.responseType,
    response_mode: parsed.responseMode,
    transaction_data: parsed.transactionData,
    qr_code: parsed.qrCode ? qrCodeOptsToPayload(parsed.qrCode) : undefined,
    direct_post_response_redirect_uri: parsed.directPostResponseRedirectUri,
    callback: parsed.callback ? callbackOptsToPayload(parsed.callback) : undefined
  }
}

export const createAuthorizationResponseFromPayload = (payload: CreateAuthorizationResponsePayload): CreateAuthorizationResponse => {
  const parsed = CreateAuthorizationResponsePayloadSchema.parse(payload)
  return {
    correlationId: parsed.correlation_id,
    queryId: parsed.query_id,
    requestUri: parsed.request_uri,
    statusUri: parsed.status_uri,
    qrUri: parsed.qr_uri
  }
}

export const createAuthorizationResponseToPayload = (internal: CreateAuthorizationResponse): CreateAuthorizationResponsePayload => {
  const parsed = CreateAuthorizationResponseSchema.parse(internal)
  return {
    correlation_id: parsed.correlationId,
    query_id: parsed.queryId,
    request_uri: parsed.requestUri,
    status_uri: parsed.statusUri,
    qr_uri: parsed.qrUri
  }
}
