import { JWKS } from '../jwt'

// https://www.rfc-editor.org/rfc/rfc7591.html#section-2
export interface DynamicRegistrationClientMetadata {
  redirect_uris?: string[]
  token_endpoint_auth_method?: string
  grant_types?: string
  response_types?: string
  client_name?: string
  client_uri?: string
  logo_uri?: string
  scope?: string
  contacts?: string[]
  tos_uri?: string
  policy_uri?: string
  jwks_uri?: string
  jwks?: JWKS
  software_id?: string
  software_version?: string
}
