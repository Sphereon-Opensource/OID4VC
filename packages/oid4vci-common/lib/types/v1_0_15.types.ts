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
  IssuerCredentialSubject,
  MetadataDisplay,
  OID4VCICredentialFormat,
  ProofTypesSupported,
  ResponseEncryption,
  StatusListOpts,
} from './Generic.types'
import { QRCodeOpts } from './QRCode.types'
import { AuthorizationServerMetadata, AuthorizationServerType, EndpointMetadata } from './ServerMetadata'

export interface IssuerMetadataV1_0_15 {
  credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0_15> // REQUIRED. A JSON object containing a list of key value pairs, where the key is a string serving as an abstract identifier of the Credential. This identifier is RECOMMENDED to be collision resistant - it can be globally unique, but does not have to be when naming conflicts are unlikely to arise in a given use case. The value is a JSON object. The JSON object MUST conform to the structure of the Section 11.2.1.
  credential_issuer: string // REQUIRED. A Credential Issuer is identified by a case sensitive URL using the https scheme that contains scheme, host and, optionally, port number and path components, but no query or fragment components.
  credential_endpoint: string // REQUIRED. URL of the OP's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  nonce_endpoint?: string // OPTIONAL. URL of the Credential Issuer's Nonce Endpoint, as defined in Section 7. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Nonce Endpoint.
  authorization_servers?: string[] // OPTIONAL. Array of strings that identify the OAuth 2.0 Authorization Servers (as defined in [RFC8414]) the Credential Issuer relies on for authorization. If this element is omitted, the entity providing the Credential Issuer is also acting as the AS, i.e. the Credential Issuer's identifier is used as the OAuth 2.0 Issuer value to obtain the Authorization Server metadata as per [RFC8414].
  deferred_credential_endpoint?: string // OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint, as defined in Section 9. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Deferred Credential Endpoint.
  notification_endpoint?: string // OPTIONAL. URL of the Credential Issuer's Notification Endpoint, as defined in Section 10. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Notification Endpoint.
  credential_response_encryption?: ResponseEncryption // OPTIONAL. Object containing information about whether the Credential Issuer supports encryption of the Credential Response on top of TLS.
  batch_credential_issuance?: BatchCredentialIssuance // OPTIONAL. Object containing information about the Credential Issuer's supports for batch issuance of Credentials on the Credential Endpoint. The presence of this parameter means that the issuer supports the proofs parameter in the Credential Request so can issue more than one Verifiable Credential for the same Credential Dataset in a single request/response.
  token_endpoint?: string // OPTIONAL. URL of the token endpoint.
  display?: MetadataDisplay[] // OPTIONAL. An array of objects, where each object contains display properties of a Credential Issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
  authorization_challenge_endpoint?: string // OPTIONAL. URL of the Credential Issuer's Authorization Challenge Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components. Described on https://www.ietf.org/archive/id/draft-parecki-oauth-first-party-apps-02.html#name-authorization-challenge-end
  signed_metadata?: string // OPTIONAL. String that is a signed JWT. This JWT contains Credential Issuer metadata parameters as claims.

  [x: string]: unknown
}

export interface BatchCredentialIssuance {
  batch_size: number // REQUIRED. Integer value specifying the maximum array size for the proofs parameter in a Credential Request.
}

export type CredentialDefinitionJwtVcJsonV1_0_15 = {
  type: string[] // REQUIRED. JSON array designating the types a certain credential type supports
  credentialSubject?: IssuerCredentialSubject // OPTIONAL. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the verifiable credential to be issued.
}

export type CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15 = {
  '@context': string[] // REQUIRED. JSON array as defined in [VC_DATA], Section 4.1.
  type: string[] // REQUIRED. JSON array designating the types a certain credential type supports
  credentialSubject?: IssuerCredentialSubject // OPTIONAL. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value MAY be a dictionary, which allows to represent the full (potentially deeply nested) structure of the verifiable credential to be issued.
}

export type CredentialConfigurationSupportedV1_0_15 = CredentialConfigurationSupportedCommonV1_0_15 &
  (
    | CredentialConfigurationSupportedSdJwtVcV1_0_15
    | CredentialConfigurationSupportedJwtVcJsonV1_0_15
    | CredentialConfigurationSupportedJwtVcJsonLdAndLdpVcV1_0_15
    | CredentialConfigurationSupportedMsoMdocV1_0_15
  )

export type CredentialConfigurationSupportedCommonV1_0_15 = {
  format: OID4VCICredentialFormat | string // REQUIRED. A JSON string identifying the format of this credential, e.g. jwt_vc_json or ldp_vc.
  scope?: string // OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this particular Credential. The value can be the same across multiple credential_configurations_supported objects. The Authorization Server MUST be able to uniquely identify the Credential Issuer based on the scope value. The Wallet can use this value in the Authorization Request as defined in Section 5.1.2. Scope values in this Credential Issuer metadata MAY duplicate those in the scopes_supported parameter of the Authorization Server.
  cryptographic_binding_methods_supported?: string[] // OPTIONAL. Array of case sensitive strings that identify how the Credential is bound to the identifier of the End-User who possesses the Credential
  credential_signing_alg_values_supported?: string[] // OPTIONAL. Array of case sensitive strings that identify the algorithms that the Issuer uses to sign the issued Credential. Algorithm names used are determined by the Credential Format and are defined in Appendix A.
  proof_types_supported?: ProofTypesSupported // OPTIONAL. Object that describes specifics of the key proof(s) that the Credential Issuer supports. This object contains a list of name/value pairs, where each name is a unique identifier of the supported proof type(s).
  display?: CredentialsSupportedDisplay[] // OPTIONAL. An array of objects, where each object contains the display properties of the supported credential for a certain language
  [x: string]: unknown
}

export interface CredentialConfigurationSupportedSdJwtVcV1_0_15 extends CredentialConfigurationSupportedCommonV1_0_15 {
  format: 'dc+sd-jwt' | 'vc+sd-jwt' // REQUIRED. Updated format identifier for SD-JWT VC to align with the media type in draft -06 of [I-D.ietf-oauth-sd-jwt-vc]
  vct: string // REQUIRED. String designating the type of a Credential, as defined in [I-D.ietf-oauth-sd-jwt-vc].
  claims?: ClaimsDescriptionV1_0_15[] // OPTIONAL. Array of claims description objects using claims path pointers as defined in Appendix C.
  order?: string[] // OPTIONAL. An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export interface CredentialConfigurationSupportedMsoMdocV1_0_15 extends CredentialConfigurationSupportedCommonV1_0_15 {
  format: 'mso_mdoc' // REQUIRED. Format identifier for ISO mDL credentials
  doctype: string // REQUIRED. String identifying the Credential type, as defined in [ISO.18013-5].
  claims?: ClaimsDescriptionV1_0_15[] // OPTIONAL. Array of claims description objects using claims path pointers as defined in Appendix C.
  order?: string[] // OPTIONAL. An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export interface CredentialConfigurationSupportedJwtVcJsonV1_0_15 extends CredentialConfigurationSupportedCommonV1_0_15 {
  format: 'jwt_vc_json' | 'jwt_vc' // REQUIRED. jwt_vc added for backward compat
  credential_definition: CredentialDefinitionJwtVcJsonV1_0_15 // REQUIRED. Object containing the detailed description of the Credential type.
  claims?: ClaimsDescriptionV1_0_15[] // OPTIONAL. Array of claims description objects using claims path pointers as defined in Appendix C.
  order?: string[] // OPTIONAL. An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

export interface CredentialConfigurationSupportedJwtVcJsonLdAndLdpVcV1_0_15 extends CredentialConfigurationSupportedCommonV1_0_15 {
  format: 'ldp_vc' | 'jwt_vc_json-ld' // REQUIRED. Format identifier for JSON-LD based credentials
  credential_definition: CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15 // REQUIRED. Object containing the detailed description of the Credential type.
  claims?: ClaimsDescriptionV1_0_15[] // OPTIONAL. Array of claims description objects using claims path pointers as defined in Appendix C.
  order?: string[] // OPTIONAL. An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
}

// Claims description using path pointers as per v15 spec change to syntax of credential metadata
export interface ClaimsDescriptionV1_0_15 {
  path: (string | number | null)[] // REQUIRED. The value MUST be a non-empty array representing a claims path pointer that specifies the path to a claim within the credential, as defined in Appendix C.
  mandatory?: boolean // OPTIONAL. Boolean which, when set to true, indicates that the Credential Issuer will always include this claim in the issued Credential. If set to false, the claim is not included in the issued Credential if the wallet did not request the inclusion of the claim, and/or if the Credential Issuer chose to not include the claim. If the mandatory parameter is omitted, the default value is false.
  display?: CredentialsSupportedDisplay[] // OPTIONAL. Array of objects, where each object contains display properties of a certain claim in the Credential for a certain language.
}

export type CredentialRequestV1_0_15ResponseEncryption = {
  jwk: JWK // REQUIRED. JWK containing the key material for encryption
  alg: AlgValue // REQUIRED. JWE algorithm for encryption
  enc: EncValue // REQUIRED. JWE encryption method
}

export interface CredentialRequestV1_0_15Common extends ExperimentalSubjectIssuance {
  credential_response_encryption?: CredentialRequestV1_0_15ResponseEncryption // OPTIONAL. Object containing information for encrypting the Credential Response. If this request element is not present, the corresponding credential response returned is not encrypted.
  proof?: ProofOfPossession // OPTIONAL. Object providing a single proof of possession of the cryptographic key material to which the issued Credential instance will be bound to. proof parameter MUST NOT be present if proofs parameter is used.
  proofs?: ProofOfPossessionMap // OPTIONAL. Object providing one or more proof of possessions of the cryptographic key material to which the issued Credential instances will be bound to. The proofs parameter MUST NOT be present if proof parameter is used.
  issuer_state?: string // OPTIONAL. We allow sending a issuer state back to the credential offer in case an auth code flow is used with an external AS and no nonces are used (not recommended), but does allow to integrate any OIDC server
}

export interface ProofOfPossessionMap {
  [proofType: string]: ProofOfPossession[] // Array of proofs for each proof type - proofs object contains exactly one parameter named as the proof type
}

// Main credential request type for v15 - removes format and format-specific parameters from Credential Request
export type CredentialRequestV1_0_15 = CredentialRequestV1_0_15Common &
  (CredentialRequestV1_0_15CredentialIdentifier | CredentialRequestV1_0_15CredentialConfigurationId)

export interface CredentialRequestV1_0_15CredentialIdentifier extends CredentialRequestV1_0_15Common {
  credential_identifier: string // REQUIRED when an Authorization Details of type openid_credential was returned from the Token Response. It MUST NOT be used otherwise. A string that identifies a Credential Dataset that is requested for issuance. When this parameter is used, the credential_configuration_id MUST NOT be present.
  credential_configuration_id?: undefined // MUST NOT be present when credential_identifier is used.
}

export interface CredentialRequestV1_0_15CredentialConfigurationId extends CredentialRequestV1_0_15Common {
  credential_configuration_id: string // REQUIRED if a credential_identifiers parameter was not returned from the Token Response as part of the authorization_details parameter. It MUST NOT be used otherwise. String that uniquely identifies one of the keys in the name/value pairs stored in the credential_configurations_supported Credential Issuer metadata.
  credential_identifier?: undefined // MUST NOT be present when credential_configuration_id is used.
}

export interface CredentialOfferV1_0_15 {
  credential_offer?: CredentialOfferPayloadV1_0_15 // OPTIONAL. Object with the Credential Offer parameters. This MUST NOT be present when the credential_offer_uri parameter is present.
  credential_offer_uri?: string // OPTIONAL. String that is a URL using the https scheme referencing a resource containing a JSON object with the Credential Offer parameters. This MUST NOT be present when the credential_offer parameter is present.
}

export interface CredentialOfferRESTRequestV1_0_15 extends Partial<CredentialOfferPayloadV1_0_15> {
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

export interface CredentialOfferPayloadV1_0_15 {
  /**
   * REQUIRED. The URL of the Credential Issuer, as defined in Section 11.2.1, from which the Wallet is requested to
   * obtain one or more Credentials. The Wallet uses it to obtain the Credential Issuer's Metadata following the steps
   * defined in Section 11.2.2.
   */
  credential_issuer: string

  /**
   * REQUIRED. Array of unique strings that each identify one of the keys in the name/value pairs stored in
   * the credential_configurations_supported Credential Issuer metadata. The Wallet uses these string values
   * to obtain the respective object that contains information about the Credential being offered as defined
   * in Section 11.2.3. For example, these string values can be used to obtain scope values to be used in
   * the Authorization Request.
   */
  credential_configuration_ids: string[]

  /**
   * OPTIONAL. Object indicating to the Wallet the Grant Types the Credential Issuer's Authorization Server is prepared
   * to process for this Credential Offer. Every grant is represented by a name/value pair. The name is the Grant Type identifier;
   * the value is an object that contains parameters either determining the way the Wallet MUST use the particular grant and/or
   * parameters the Wallet MUST send with the respective request(s). If grants is not present or is empty, the Wallet MUST determine
   * the Grant Types the Credential Issuer's Authorization Server supports using the respective metadata. When multiple grants are present,
   * it is at the Wallet's discretion which one to use.
   */
  grants?: Grant

  /**
   * OPTIONAL. Some implementations might include a client_id in the offer. For instance EBSI in a same-device flow. (Cross-device tucks it in the state JWT)
   */
  client_id?: string
}

// Credential Response for v15 - credential response always returns an array when not returning a transaction_id
export interface CredentialResponseV1_0_15 extends ExperimentalSubjectIssuance {
  credentials?: CredentialResponseCredentialV1_0_15[] // OPTIONAL. Contains an array of one or more issued Credentials. It MUST NOT be used if the transaction_id parameter is present. The elements of the array MUST be objects.
  transaction_id?: string // OPTIONAL. String identifying a Deferred Issuance transaction. This parameter is contained in the response if the Credential Issuer cannot immediately issue the Credential. The value is subsequently used to obtain the respective Credential with the Deferred Credential Endpoint. It MUST NOT be used if the credentials parameter is present. It MUST be invalidated after the Credential for which it was meant has been obtained by the Wallet.
  notification_id?: string // OPTIONAL. String identifying one or more Credentials issued in one Credential Response. It MUST be included in the Notification Request as defined in Section 10. It MUST NOT be present if the credentials parameter is not present.
}

export interface CredentialResponseCredentialV1_0_15 {
  credential: string | object // REQUIRED. Contains one issued Credential. It MAY be a string or an object, depending on the Credential Format. See Appendix A for the Credential Format-specific encoding requirements.
  // Additional metadata can be included here with the option for additional meta-data
}

// Deferred Credential Response for v15 - deferred credential response always returns an array (same as credential response)
export interface DeferredCredentialResponseV1_0_15 {
  credentials: CredentialResponseCredentialV1_0_15[] // REQUIRED. Array of issued credentials using the same structure as the immediate credential response.
  notification_id?: string // OPTIONAL. String identifying one or more Credentials issued in one Credential Response.
}

// Token Response with credential_identifiers support - add an option to return credential_identifiers in the Token Response and use them in the Credential Request, when scopes are used in the Authorization Request
export interface TokenResponseV1_0_15 {
  access_token: string
  token_type: string
  expires_in?: number
  refresh_token?: string
  scope?: string
  authorization_details?: AuthorizationDetailsV1_0_15[]
  // Note: removes c_nonce and c_nonce_expires_in from the Token Response as they are now obtained from the Nonce Endpoint
}

export interface AuthorizationDetailsV1_0_15 {
  type: 'openid_credential' // REQUIRED. JSON string that determines the authorization details type. MUST be set to openid_credential for the purpose of this specification.
  credential_configuration_id?: string // OPTIONAL. String specifying a unique identifier of the Credential being described in the credential_configurations_supported map
  credential_identifiers?: string[] // REQUIRED when the authorization_details parameter is used to request issuance of a Credential of a certain Credential Configuration. Array of strings, each uniquely identifying a Credential Dataset that can be issued using the Access Token returned in this response.
  locations?: string[] // OPTIONAL. If the Credential Issuer metadata contains an authorization_server parameter, the authorization detail's locations common data field MUST be set to the Credential Issuer Identifier value.
  [x: string]: unknown
}

// Nonce Endpoint - added a Nonce Endpoint where a Client can acquire a fresh c_nonce value without the overhead of a full Credential Request
export interface NonceRequestV1_0_15 {
  // Empty request body - The request for a nonce is made by sending an HTTP POST request to the URL provided in the nonce_endpoint Credential Issuer Metadata parameter.
}

export interface NonceResponseV1_0_15 {
  c_nonce: string // REQUIRED. String containing a nonce to be used when creating a proof of possession of the key proof
  // Note: removes c_nonce_expires_in from Nonce Endpoint response
}

// Error responses updated for v15 - removes c_nonce and c_nonce_expires_in from the Credential Error Response
export interface CredentialErrorResponseV1_0_15 {
  error: string // REQUIRED. The error parameter SHOULD be a single ASCII error code
  error_description?: string // OPTIONAL. Human-readable ASCII text providing additional information
  error_uri?: string // OPTIONAL. A URI identifying a human-readable web page with information about the error
  // Note: c_nonce and c_nonce_expires_in removed from error response
}

// Proof types for v15 - removes CWT proof type, adds key attestation as additional information in a proof of possession and new proof type
export interface ProofTypesV1_0_15 {
  jwt?: ProofTypeV1_0_15 // OPTIONAL. JWT proof type support
  ldp_vp?: ProofTypeV1_0_15 // OPTIONAL. Linked Data Proof VP support
  attestation?: ProofTypeV1_0_15 // OPTIONAL. New attestation proof type for key attestation
}

export interface ProofTypeV1_0_15 {
  proof_signing_alg_values_supported: string[] // REQUIRED. Array of case sensitive strings that identify the algorithms that the Issuer supports for this proof type.
  key_attestations_required?: KeyAttestationsRequiredV1_0_15 // OPTIONAL. Object that describes the requirement for key attestations, which the Credential Issuer expects the Wallet to send within the proof of the Credential Request.
}

export interface KeyAttestationsRequiredV1_0_15 {
  key_storage?: string[] // OPTIONAL. Array defining values for key storage attack potential resistance
  user_authentication?: string[] // OPTIONAL. Array defining values for user authentication attack potential resistance
}

// Key Attestation JWT format - add key attestation as additional information in a proof of possession
export interface KeyAttestationJWT {
  // JOSE Header
  alg: string // REQUIRED. A digital signature algorithm identifier such as per IANA "JSON Web Signature and Encryption Algorithms" registry
  typ: 'keyattestation+jwt' // REQUIRED. MUST be keyattestation+jwt, which explicitly types the key attestation JWT
  kid?: string // OPTIONAL. Key identifier
  x5c?: string[] // OPTIONAL. Certificate chain corresponding to the key used to sign the JWT
  trust_chain?: string[] // OPTIONAL. Trust chain for validation

  // JWT Claims
  iss?: string // OPTIONAL. Issuer of the key attestation
  iat: number // REQUIRED. Integer for the time at which the key attestation was issued
  exp?: number // OPTIONAL. Integer for the time at which the key attestation and the key(s) it is attesting expire
  attested_keys: JWK[] // REQUIRED. Array of attested keys from the same key storage component
  key_storage?: string[] // OPTIONAL. Array of case sensitive strings that assert the attack potential resistance of the key storage component
  user_authentication?: string[] // OPTIONAL. Array of case sensitive strings that assert the attack potential resistance of the user authentication methods
  certification?: string // OPTIONAL. A String that contains a URL that links to the certification of the key storage component
  nonce?: string // OPTIONAL. String that represents a nonce provided by the Issuer to prove that a key attestation was freshly generated
  status?: object // OPTIONAL. JSON Object representing the supported revocation check mechanisms
}

// Wallet Attestation format - add section on Wallet Attestations
export interface WalletAttestationJWT {
  // JOSE Header
  typ: 'oauth-client-attestation+jwt' // REQUIRED. Type header for wallet attestation
  alg: string // REQUIRED. Signature algorithm
  kid?: string // OPTIONAL. Key identifier

  // JWT Claims
  iss: string // REQUIRED. Issuer of the wallet attestation
  sub: string // REQUIRED. Subject (wallet identifier)
  wallet_name?: string // OPTIONAL. String containing a human-readable name of the Wallet
  wallet_link?: string // OPTIONAL. String containing a URL to get further information about the Wallet and the Wallet Provider
  nbf?: number // OPTIONAL. Not before time
  exp?: number // OPTIONAL. Expiration time
  cnf: {
    jwk: JWK // REQUIRED. Confirmation key for proof of possession
  }
  status?: object // OPTIONAL. Status mechanism for the Wallet Attestation
}

export interface CredentialIssuerMetadataOptsV1_0_15 {
  credential_endpoint: string // REQUIRED. URL of the Credential Issuer's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  nonce_endpoint?: string // OPTIONAL. URL of the Credential Issuer's Nonce Endpoint. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Nonce Endpoint.
  deferred_credential_endpoint?: string // OPTIONAL. URL of the Credential Issuer's Deferred Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Deferred Credential Endpoint.
  notification_endpoint?: string // OPTIONAL. URL of the Credential Issuer's Notification Endpoint. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Notification Endpoint.
  credential_response_encryption?: ResponseEncryption // OPTIONAL. Object containing information about whether the Credential Issuer supports encryption of the Credential Response on top of TLS.
  batch_credential_issuance?: BatchCredentialIssuance // OPTIONAL. Object containing information about the Credential Issuer's supports for batch issuance of Credentials on the Credential Endpoint.
  credential_identifiers_supported?: boolean // OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning credential_identifiers parameter in the authorization_details Token Response parameter, with true indicating support. If omitted, the default value is false.
  credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0_15> // REQUIRED. Object that describes specifics of the Credential that the Credential Issuer supports issuance of.
  credential_issuer: string // REQUIRED. The Credential Issuer's identifier.
  authorization_servers?: string[] // OPTIONAL. Array of strings that identify the OAuth 2.0 Authorization Servers the Credential Issuer relies on for authorization.
  signed_metadata?: string // OPTIONAL. String that is a signed JWT. This JWT contains Credential Issuer metadata parameters as claims.
  display?: MetadataDisplay[] // OPTIONAL. Array of objects, where each object contains display properties of a Credential Issuer for a certain language.
  authorization_challenge_endpoint?: string // OPTIONAL. URL of the Credential Issuer's Authorization Challenge Endpoint.
  token_endpoint?: string // OPTIONAL. URL of the token endpoint.
  credential_supplier_config?: CredentialSupplierConfig // OPTIONAL. Configuration for credential suppliers.
}

export const credentialIssuerMetadataFieldNamesV1_0_15: Array<keyof CredentialIssuerMetadataOptsV1_0_15> = [
  'credential_issuer',
  'credential_configurations_supported',
  'credential_endpoint',
  'nonce_endpoint',
  'deferred_credential_endpoint',
  'notification_endpoint',
  'credential_response_encryption',
  'batch_credential_issuance',
  'authorization_servers',
  'token_endpoint',
  'display',
  'credential_supplier_config',
  'credential_identifiers_supported',
  'signed_metadata',
  'authorization_challenge_endpoint',
] as const

export interface EndpointMetadataResultV1_0_15 extends EndpointMetadata {
  authorizationServerType: AuthorizationServerType
  authorizationServerMetadata?: AuthorizationServerMetadata
  credentialIssuerMetadata?: Partial<AuthorizationServerMetadata> & IssuerMetadataV1_0_15
}

export interface CredentialIssuerMetadataV1_0_15 extends CredentialIssuerMetadataOptsV1_0_15, Partial<AuthorizationServerMetadata> {
  authorization_servers?: string[] // OPTIONAL. Array of strings that identify the OAuth 2.0 Authorization Servers the Credential Issuer relies on for authorization.
  credential_endpoint: string // REQUIRED. URL of the Credential Issuer's Credential Endpoint.
  credential_configurations_supported: Record<string, CredentialConfigurationSupportedV1_0_15> // REQUIRED. Supported credential configurations.
  credential_issuer: string // REQUIRED. The Credential Issuer's identifier.
  credential_response_encryption_alg_values_supported?: string // OPTIONAL. Array containing a list of the JWE encryption algorithms (alg values) supported.
  credential_response_encryption_enc_values_supported?: string // OPTIONAL. Array containing a list of the JWE encryption algorithms (enc values) supported.
  require_credential_response_encryption?: boolean // OPTIONAL. Boolean value specifying whether the Credential Issuer requires additional encryption on top of TLS.
  credential_identifiers_supported?: boolean // OPTIONAL. Boolean value specifying whether the Credential Issuer supports returning credential_identifiers parameter.
  nonce_endpoint?: string // OPTIONAL. URL of the Credential Issuer's Nonce Endpoint, as defined in Section 7. This URL MUST use the https scheme and MAY contain port, path, and query parameter components. If omitted, the Credential Issuer does not support the Nonce Endpoint
}

export interface NotificationResponseV1_0_15 {
  // Success responses typically return 204 No Content - When the Credential Issuer has successfully received the Notification Request from the Wallet, it MUST respond with an HTTP status code in the 2xx range.
}

export interface NotificationErrorResponseV1_0_15 {
  error: 'invalid_notification_id' | 'invalid_notification_request' // REQUIRED. Error code for notification failures.
  error_description?: string // OPTIONAL. Human-readable error description.
}

// Authorization Server metadata extension for v15 - remove use of the authorization_pending and slow_down error codes
export interface AuthorizationServerMetadataV1_0_15 extends AuthorizationServerMetadata {
  'pre-authorized_grant_anonymous_access_supported'?: boolean // OPTIONAL. A boolean indicating whether the Credential Issuer accepts a Token Request with a Pre-Authorized Code but without a client_id. The default is false.
  // Note: authorization_pending and slow_down error codes removed in v14
}
