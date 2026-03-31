import { JWK } from '@sphereon/oid4vc-common'

import { ExperimentalSubjectIssuance } from '../experimental/holder-vci'

import { ProofOfPossession } from './CredentialIssuance.types'
import {
  AlgValue,
  CredentialDataSupplierInput,
  CredentialOfferMode,
  CredentialsSupportedDisplay,
  CredentialSupplierConfig,
  EncValue,
  Grant,
  MetadataDisplay,
  OID4VCICredentialFormat,
  ResponseEncryption,
  StatusListOpts,
} from './Generic.types'
import { QRCodeOpts } from './QRCode.types'
import { AuthorizationServerMetadata, AuthorizationServerType, EndpointMetadata } from './ServerMetadata'
import {
  CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15,
  CredentialDefinitionJwtVcJsonV1_0_15,
  KeyAttestationJWT,
  KeyAttestationsRequiredV1_0_15,
  ProofOfPossessionMap,
  WalletAttestationJWT,
} from './v1_0_15.types'

// =====================
// Proof Types
// =====================

export interface ProofTypesV1_0 {
  jwt?: ProofTypeV1_0
  di_vp?: ProofTypeV1_0 // Renamed from ldp_vp in draft 15 to di_vp in 1.0 final
  attestation?: ProofTypeV1_0
}

export interface ProofTypeV1_0 {
  proof_signing_alg_values_supported: string[] // REQUIRED
  key_attestations_required?: KeyAttestationsRequiredV1_0_15 // OPTIONAL. Reuses same structure from d15
}

export type ProofTypesSupportedV1_0 = {
  [key: string]: ProofTypeV1_0
}

// =====================
// Credential Configuration
// =====================

export type CredentialConfigurationSupportedCommonV1_0 = {
  format: OID4VCICredentialFormat | string // REQUIRED
  scope?: string // OPTIONAL
  cryptographic_binding_methods_supported?: string[] // OPTIONAL
  cryptographic_suites_supported?: string[] // OPTIONAL. Replaces credential_signing_alg_values_supported from draft 15
  credential_signing_alg_values_supported?: string[] // Keep for backward compat with issuers that use draft 15 naming
  proof_types_supported?: ProofTypesSupportedV1_0 // OPTIONAL
  display?: CredentialsSupportedDisplay[] // OPTIONAL
  [x: string]: unknown
}

export interface CredentialConfigurationSupportedSdJwtVcV1_0 extends CredentialConfigurationSupportedCommonV1_0 {
  format: 'dc+sd-jwt' | 'vc+sd-jwt'
  vct: string // REQUIRED
  claims?: ClaimsDescriptionV1_0[] // OPTIONAL
  order?: string[] // OPTIONAL
}

export interface CredentialConfigurationSupportedJwtVcJsonV1_0 extends CredentialConfigurationSupportedCommonV1_0 {
  format: 'jwt_vc_json' | 'jwt_vc'
  credential_definition: CredentialDefinitionJwtVcJsonV1_0_15 // REQUIRED. Reuses same structure
  claims?: ClaimsDescriptionV1_0[] // OPTIONAL
  order?: string[] // OPTIONAL
}

export interface CredentialConfigurationSupportedJwtVcJsonLdAndLdpVcV1_0 extends CredentialConfigurationSupportedCommonV1_0 {
  format: 'ldp_vc' | 'jwt_vc_json-ld'
  credential_definition: CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15 // REQUIRED. Reuses same structure
  claims?: ClaimsDescriptionV1_0[] // OPTIONAL
  order?: string[] // OPTIONAL
}

export interface CredentialConfigurationSupportedMsoMdocV1_0 extends CredentialConfigurationSupportedCommonV1_0 {
  format: 'mso_mdoc'
  doctype: string // REQUIRED
  claims?: ClaimsDescriptionV1_0[] // OPTIONAL
  order?: string[] // OPTIONAL
}

export type CredentialConfigurationSupportedV1_0 = CredentialConfigurationSupportedCommonV1_0 &
  (
    | CredentialConfigurationSupportedSdJwtVcV1_0
    | CredentialConfigurationSupportedJwtVcJsonV1_0
    | CredentialConfigurationSupportedJwtVcJsonLdAndLdpVcV1_0
    | CredentialConfigurationSupportedMsoMdocV1_0
  )

// Claims description - same structure as draft 15 (using path pointers)
export interface ClaimsDescriptionV1_0 {
  path: (string | number | null)[] // REQUIRED. Claims path pointer
  mandatory?: boolean // OPTIONAL. Defaults to false
  display?: CredentialsSupportedDisplay[] // OPTIONAL
}

// =====================
// Issuer Metadata
// =====================

export interface IssuerMetadataV1_0 {
  credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0> // REQUIRED
  credential_issuer: string // REQUIRED
  credential_endpoint: string // REQUIRED
  token_endpoint?: string // OPTIONAL (REQUIRED per spec, but may come from AS metadata)
  nonce_endpoint?: string // OPTIONAL
  authorization_servers?: string[] // OPTIONAL
  authorization_endpoint?: string // OPTIONAL
  deferred_credential_endpoint?: string // OPTIONAL
  notification_endpoint?: string // OPTIONAL
  credential_response_encryption?: ResponseEncryption // OPTIONAL
  batch_credential_issuance_supported?: boolean // OPTIONAL. Changed from object (d15) to boolean (1.0 final)
  credential_issuer_public_key?: object // OPTIONAL. JWKS with issuer's public keys. New in 1.0 final
  display?: MetadataDisplay[] // OPTIONAL
  authorization_challenge_endpoint?: string // OPTIONAL
  signed_metadata?: string // OPTIONAL
  [x: string]: unknown
}

// =====================
// Credential Request
// =====================

export type CredentialRequestV1_0ResponseEncryption = {
  jwk: JWK // REQUIRED
  alg: AlgValue // REQUIRED
  enc: EncValue // REQUIRED
}

export interface CredentialRequestV1_0Common extends ExperimentalSubjectIssuance {
  credential_configuration_id: string // REQUIRED always in 1.0 final
  credential_identifiers?: string[] // OPTIONAL array. Replaces singular credential_identifier from d15
  credential_response_encryption?: CredentialRequestV1_0ResponseEncryption // OPTIONAL
  proof?: ProofOfPossession // OPTIONAL
  proofs?: ProofOfPossessionMap // OPTIONAL
}

// In 1.0 final, credential_configuration_id is always required and credential_identifiers is an optional array
// No discriminated union needed like in d15
export type CredentialRequestV1_0 = CredentialRequestV1_0Common

// =====================
// Credential Response
// =====================

// 1.0 final: singular credential field (NOT array, NOT wrapped)
export interface CredentialResponseV1_0 extends ExperimentalSubjectIssuance {
  credential?: string | object // OPTIONAL. Singular credential value. Mutually exclusive with transaction_id
  transaction_id?: string // OPTIONAL. Deferred issuance indicator. Mutually exclusive with credential
  acceptance_token?: string // OPTIONAL. Token for deferred issuance acknowledgment
  interval?: number // OPTIONAL. Seconds before retrying deferred request
  c_nonce?: string // OPTIONAL. Fresh nonce for subsequent requests. Back in 1.0 final
  c_nonce_expires_in?: number // OPTIONAL. Nonce validity period. Back in 1.0 final
  notification_id?: string // OPTIONAL
}

// Deferred Credential Response - singular credential
export interface DeferredCredentialResponseV1_0 {
  credential: string | object // REQUIRED
  acceptance_token?: string // OPTIONAL. For subsequent deferred requests
  interval?: number // OPTIONAL
  c_nonce?: string // OPTIONAL
  c_nonce_expires_in?: number // OPTIONAL
  notification_id?: string // OPTIONAL
}

// =====================
// Token Response
// =====================

// 1.0 final: c_nonce and c_nonce_expires_in are back as OPTIONAL
export interface TokenResponseV1_0 {
  access_token: string
  token_type: string
  expires_in?: number
  refresh_token?: string
  scope?: string
  authorization_details?: AuthorizationDetailsV1_0[]
  c_nonce?: string // OPTIONAL. Back in 1.0 final
  c_nonce_expires_in?: number // OPTIONAL. Back in 1.0 final
}

// =====================
// Authorization Details
// =====================

export interface AuthorizationDetailsV1_0 {
  type: 'openid_credential' // REQUIRED
  credential_configuration_id: string // REQUIRED in 1.0 final (was optional in d15)
  credential_identifiers?: string[] // OPTIONAL. Array of credential dataset identifiers
  locations?: string[] // OPTIONAL
  [x: string]: unknown
}

// =====================
// Nonce Endpoint
// =====================

export interface NonceRequestV1_0 {
  // Empty request body
}

// 1.0 final: both fields REQUIRED
export interface NonceResponseV1_0 {
  c_nonce: string // REQUIRED
  c_nonce_expires_in: number // REQUIRED. Was absent in d15 nonce response
}

// =====================
// Error Response
// =====================

// 1.0 final: c_nonce and c_nonce_expires_in are back in error response
export interface CredentialErrorResponseV1_0 {
  error: string // REQUIRED
  error_description?: string // OPTIONAL
  error_uri?: string // OPTIONAL
  c_nonce?: string // OPTIONAL. Back in 1.0 final
  c_nonce_expires_in?: number // OPTIONAL. Back in 1.0 final
}

// =====================
// Credential Offer (structurally identical to d15)
// =====================

export interface CredentialOfferV1_0 {
  credential_offer?: CredentialOfferPayloadV1_0
  credential_offer_uri?: string
}

export interface CredentialOfferPayloadV1_0 {
  credential_issuer: string // REQUIRED
  credential_configuration_ids: string[] // REQUIRED
  grants?: Grant // OPTIONAL
  client_id?: string // OPTIONAL
}

export interface CredentialOfferRESTRequestV1_0 extends Partial<CredentialOfferPayloadV1_0> {
  redirectUri?: string
  baseUri?: string
  scheme?: string
  correlationId?: string
  sessionLifeTimeInSec?: number
  pinLength?: number
  qrCodeOpts?: QRCodeOpts
  client_id?: string
  credentialDataSupplierInput?: CredentialDataSupplierInput
  statusListOpts?: Array<StatusListOpts>
  offerMode?: CredentialOfferMode
}

// =====================
// Issuer Metadata Builder Types
// =====================

export interface CredentialIssuerMetadataOptsV1_0 {
  credential_endpoint: string // REQUIRED
  nonce_endpoint?: string // OPTIONAL
  deferred_credential_endpoint?: string // OPTIONAL
  notification_endpoint?: string // OPTIONAL
  credential_response_encryption?: ResponseEncryption // OPTIONAL
  batch_credential_issuance_supported?: boolean // OPTIONAL. Boolean in 1.0 (was object in d15)
  credential_issuer_public_key?: object // OPTIONAL. New in 1.0 final
  credential_identifiers_supported?: boolean // OPTIONAL
  credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0> // REQUIRED
  credential_issuer: string // REQUIRED
  authorization_servers?: string[] // OPTIONAL
  signed_metadata?: string // OPTIONAL
  display?: MetadataDisplay[] // OPTIONAL
  authorization_challenge_endpoint?: string // OPTIONAL
  token_endpoint?: string // OPTIONAL
  credential_supplier_config?: CredentialSupplierConfig // OPTIONAL
}

export interface CredentialIssuerMetadataV1_0 extends CredentialIssuerMetadataOptsV1_0, Partial<AuthorizationServerMetadata> {
  authorization_servers?: string[] // OPTIONAL
  credential_endpoint: string // REQUIRED
  credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0> // REQUIRED
  credential_issuer: string // REQUIRED
  credential_response_encryption_alg_values_supported?: string // OPTIONAL
  credential_response_encryption_enc_values_supported?: string // OPTIONAL
  require_credential_response_encryption?: boolean // OPTIONAL
  credential_identifiers_supported?: boolean // OPTIONAL
  nonce_endpoint?: string // OPTIONAL
}

export const credentialIssuerMetadataFieldNamesV1_0: Array<keyof CredentialIssuerMetadataOptsV1_0> = [
  'credential_issuer',
  'credential_configurations_supported',
  'credential_endpoint',
  'nonce_endpoint',
  'deferred_credential_endpoint',
  'notification_endpoint',
  'credential_response_encryption',
  'batch_credential_issuance_supported',
  'credential_issuer_public_key',
  'authorization_servers',
  'token_endpoint',
  'display',
  'credential_supplier_config',
  'credential_identifiers_supported',
  'signed_metadata',
  'authorization_challenge_endpoint',
] as const

export interface EndpointMetadataResultV1_0 extends EndpointMetadata {
  authorizationServerType: AuthorizationServerType
  authorizationServerMetadata?: AuthorizationServerMetadata
  credentialIssuerMetadata?: Partial<AuthorizationServerMetadata> & IssuerMetadataV1_0
}

// =====================
// Notification (same structure as d15)
// =====================

export interface NotificationResponseV1_0 {
  // Success responses return 204 No Content
}

export interface NotificationErrorResponseV1_0 {
  error: 'invalid_notification_id' | 'invalid_notification_request' // REQUIRED
  error_description?: string // OPTIONAL
}

// =====================
// Authorization Server metadata extension
// =====================

export interface AuthorizationServerMetadataV1_0 extends AuthorizationServerMetadata {
  'pre-authorized_grant_anonymous_access_supported'?: boolean // OPTIONAL
}

// Re-export reused types from d15 for convenience
export type { KeyAttestationJWT, WalletAttestationJWT, ProofOfPossessionMap }
