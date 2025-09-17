import { LanguageTagUtils, removeNullUndefined } from '../helpers'
import {
  ClientMetadataOpts,
  PassBy,
  RequestClientMetadataPayloadProperties,
  RequestRegistrationPayloadProperties,
  RPRegistrationMetadataOpts,
  RPRegistrationMetadataPayload,
  SIOPErrors,
  SupportedVersion,
} from '../types'
import { CreateAuthorizationRequestOpts } from './types'

export const assertValidRequestRegistrationOpts = (opts: ClientMetadataOpts) => {
  if (!opts) {
    throw new Error(SIOPErrors.REGISTRATION_NOT_SET)
  } else if (opts.passBy !== PassBy.REFERENCE && opts.passBy !== PassBy.VALUE) {
    throw new Error(SIOPErrors.REGISTRATION_OBJECT_TYPE_NOT_SET)
  } else if (opts.passBy === PassBy.REFERENCE && !opts.reference_uri) {
    throw new Error(SIOPErrors.NO_REFERENCE_URI)
  }
}

const createRequestRegistrationPayload = async (
  opts: ClientMetadataOpts,
  metadataPayload: RPRegistrationMetadataPayload,
  version: SupportedVersion, // TODO we could remove this
): Promise<RequestRegistrationPayloadProperties | RequestClientMetadataPayloadProperties> => {
  assertValidRequestRegistrationOpts(opts)

  if (opts.passBy == PassBy.VALUE) {
      return { registration: removeNullUndefined(metadataPayload) }
  } else {
      return { registration_uri: opts.reference_uri }
  }
}

export const createRequestRegistration = async (
  clientMetadataOpts: ClientMetadataOpts,
  createRequestOpts: CreateAuthorizationRequestOpts,
): Promise<{
  payload: RequestRegistrationPayloadProperties | RequestClientMetadataPayloadProperties
  metadata: RPRegistrationMetadataPayload
  createRequestOpts: CreateAuthorizationRequestOpts
  clientMetadataOpts: ClientMetadataOpts
}> => {
  const metadata = createRPRegistrationMetadataPayload(clientMetadataOpts, createRequestOpts.version)
  const payload = await createRequestRegistrationPayload(clientMetadataOpts, metadata, createRequestOpts.version)
  return {
    payload,
    metadata,
    createRequestOpts,
    clientMetadataOpts,
  }
}

const createRPRegistrationMetadataPayload = (opts: RPRegistrationMetadataOpts, version: SupportedVersion): RPRegistrationMetadataPayload => {
  const rpRegistrationMetadataPayload = {
    id_token_signing_alg_values_supported: opts.idTokenSigningAlgValuesSupported,
    request_object_signing_alg_values_supported: opts.requestObjectSigningAlgValuesSupported,
    response_types_supported: opts.responseTypesSupported,
    scopes_supported: opts.scopesSupported,
    subject_types_supported: opts.subjectTypesSupported,
    subject_syntax_types_supported: opts.subject_syntax_types_supported || ['did:web:', 'did:ion:'],
    ...(version === SupportedVersion.OID4VP_v1 ? { vp_formats_supported: opts.vp_formats_supported } : { vp_formats: opts.vp_formats_supported }),
    client_name: opts.clientName,
    logo_uri: opts.logo_uri,
    tos_uri: opts.tos_uri,
    client_purpose: opts.client_purpose,
    client_id: opts.client_id,
  }

  const languageTagEnabledFieldsNamesMapping = new Map<string, string>()
  languageTagEnabledFieldsNamesMapping.set('clientName', 'client_name')
  languageTagEnabledFieldsNamesMapping.set('client_purpose', 'client_purpose')

  const languageTaggedFields: Map<string, string> = LanguageTagUtils.getLanguageTaggedPropertiesMapped(opts, languageTagEnabledFieldsNamesMapping)

  languageTaggedFields.forEach((value: string, key: string) => {
    const _key = key as keyof typeof rpRegistrationMetadataPayload
    rpRegistrationMetadataPayload[_key] = value
  })

  return removeNullUndefined(rpRegistrationMetadataPayload)
}
