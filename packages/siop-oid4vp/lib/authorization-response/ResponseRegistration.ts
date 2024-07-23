import { LanguageTagUtils, removeNullUndefined } from '../helpers'
import { DiscoveryMetadataOpts, DiscoveryMetadataPayload, ResponseIss, ResponseType, Schema, Scope, SigningAlgo, SubjectType } from '../types'

export const createDiscoveryMetadataPayload = (opts: DiscoveryMetadataOpts): DiscoveryMetadataPayload => {
  const discoveryMetadataPayload: DiscoveryMetadataPayload = {
    authorization_endpoint: opts.authorizationEndpoint || Schema.OPENID,
    issuer: opts.issuer ?? ResponseIss.SELF_ISSUED_V2,
    response_types_supported: opts.responseTypesSupported ?? ResponseType.ID_TOKEN,
    scopes_supported: opts?.scopesSupported || [Scope.OPENID],
    subject_types_supported: opts?.subjectTypesSupported || [SubjectType.PAIRWISE],
    id_token_signing_alg_values_supported: opts?.idTokenSigningAlgValuesSupported || [SigningAlgo.ES256K, SigningAlgo.EDDSA],
    request_object_signing_alg_values_supported: opts.requestObjectSigningAlgValuesSupported || [SigningAlgo.ES256K, SigningAlgo.EDDSA],
    subject_syntax_types_supported: opts.subject_syntax_types_supported,
    client_id: opts.client_id,
    redirect_uris: opts.redirectUris,
    client_name: opts.clientName,
    token_endpoint_auth_method: opts.tokenEndpointAuthMethod,
    application_type: opts.applicationType,
    response_types: opts.responseTypes,
    grant_types: opts.grantTypes,
    vp_formats: opts.vpFormats,
    token_endpoint: opts.tokenEndpoint,
    userinfo_endpoint: opts.userinfoEndpoint,
    jwks_uri: opts.jwksUri,
    registration_endpoint: opts.registrationEndpoint,
    response_modes_supported: opts.responseModesSupported,
    grant_types_supported: opts.grantTypesSupported,
    acr_values_supported: opts.acrValuesSupported,
    id_token_encryption_alg_values_supported: opts.idTokenEncryptionAlgValuesSupported,
    id_token_encryption_enc_values_supported: opts.idTokenEncryptionEncValuesSupported,
    userinfo_signing_alg_values_supported: opts.userinfoSigningAlgValuesSupported,
    userinfo_encryption_alg_values_supported: opts.userinfoEncryptionAlgValuesSupported,
    userinfo_encryption_enc_values_supported: opts.userinfoEncryptionEncValuesSupported,
    request_object_encryption_alg_values_supported: opts.requestObjectEncryptionAlgValuesSupported,
    request_object_encryption_enc_values_supported: opts.requestObjectEncryptionEncValuesSupported,
    token_endpoint_auth_methods_supported: opts.tokenEndpointAuthMethodsSupported,
    token_endpoint_auth_signing_alg_values_supported: opts.tokenEndpointAuthSigningAlgValuesSupported,
    display_values_supported: opts.displayValuesSupported,
    claim_types_supported: opts.claimTypesSupported,
    claims_supported: opts.claimsSupported,
    service_documentation: opts.serviceDocumentation,
    claims_locales_supported: opts.claimsLocalesSupported,
    ui_locales_supported: opts.uiLocalesSupported,
    claims_parameter_supported: opts.claimsParameterSupported,
    request_parameter_supported: opts.requestParameterSupported,
    request_uri_parameter_supported: opts.requestUriParameterSupported,
    require_request_uri_registration: opts.requireRequestUriRegistration,
    op_policy_uri: opts.opPolicyUri,
    op_tos_uri: opts.opTosUri,
    logo_uri: opts.logo_uri,
    client_purpose: opts.clientPurpose,
    id_token_types_supported: opts.idTokenTypesSupported,
  }

  const languageTagEnabledFieldsNamesMapping = new Map<string, string>()
  languageTagEnabledFieldsNamesMapping.set('clientName', 'client_name')
  languageTagEnabledFieldsNamesMapping.set('clientPurpose', 'client_purpose')

  const languageTaggedFields: Map<string, string> = LanguageTagUtils.getLanguageTaggedPropertiesMapped(opts, languageTagEnabledFieldsNamesMapping)
  languageTaggedFields.forEach((value: string, key: string) => {
    discoveryMetadataPayload[key] = value
  })

  return removeNullUndefined(discoveryMetadataPayload)
}
