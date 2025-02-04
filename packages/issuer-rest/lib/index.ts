export * from './OID4VCIServer'
export * from './oid4vci-api-functions'
export * from './expressUtils'

/**
 * Copied from openid-client
 */
export type ResponseType = 'code' | 'id_token' | 'code id_token' | 'none' | string
export type ClientAuthMethod =
  | 'client_secret_basic'
  | 'client_secret_post'
  | 'client_secret_jwt'
  | 'private_key_jwt'
  | 'tls_client_auth'
  | 'self_signed_tls_client_auth'
  | 'none'
export interface ClientMetadata {
  // important
  client_id: string
  id_token_signed_response_alg?: string
  token_endpoint_auth_method?: ClientAuthMethod
  client_secret?: string
  redirect_uris?: string[]
  response_types?: ResponseType[]
  post_logout_redirect_uris?: string[]
  default_max_age?: number
  require_auth_time?: boolean
  tls_client_certificate_bound_access_tokens?: boolean
  request_object_signing_alg?: string

  // less important
  id_token_encrypted_response_alg?: string
  id_token_encrypted_response_enc?: string
  introspection_endpoint_auth_method?: ClientAuthMethod
  introspection_endpoint_auth_signing_alg?: string
  request_object_encryption_alg?: string
  request_object_encryption_enc?: string
  revocation_endpoint_auth_method?: ClientAuthMethod
  revocation_endpoint_auth_signing_alg?: string
  token_endpoint_auth_signing_alg?: string
  userinfo_encrypted_response_alg?: string
  userinfo_encrypted_response_enc?: string
  userinfo_signed_response_alg?: string
  authorization_encrypted_response_alg?: string
  authorization_encrypted_response_enc?: string
  authorization_signed_response_alg?: string

  [key: string]: unknown
}
