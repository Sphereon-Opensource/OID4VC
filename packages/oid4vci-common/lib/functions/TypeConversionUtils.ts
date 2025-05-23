import { VCI_LOG_COMMON } from '../index'
import {
  AuthorizationDetails,
  CredentialConfigurationSupported,
  CredentialConfigurationSupportedMsoMdocV1_0_13,
  CredentialConfigurationSupportedSdJwtVcV1_0_13,
  CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_13,
  CredentialDefinitionJwtVcJsonV1_0_13,
  CredentialOfferFormatV1_0_11,
  CredentialOfferPayload,
  CredentialsSupportedLegacy,
  CredentialSupportedMsoMdoc,
  CredentialSupportedSdJwtVc,
  JsonLdIssuerCredentialDefinition,
  UniformCredentialOfferPayload,
  UniformCredentialOfferRequest,
} from '../types'

export function isW3cCredentialSupported(
  supported: CredentialConfigurationSupported | CredentialsSupportedLegacy,
): supported is Exclude<
  CredentialConfigurationSupported,
  | CredentialConfigurationSupportedMsoMdocV1_0_13
  | CredentialSupportedMsoMdoc
  | CredentialConfigurationSupportedSdJwtVcV1_0_13
  | CredentialSupportedSdJwtVc
> {
  return ['jwt_vc_json', 'jwt_vc_json-ld', 'ldp_vc', 'jwt_vc'].includes(supported.format)
}

export const getNumberOrUndefined = (input?: string): number | undefined => {
  return input && !isNaN(+input) ? +input : undefined
}

/**
 * The specs had many places where types could be expressed. This method ensures we get them in any way possible
 * @param subject
 */
export function getTypesFromObject(
  subject:
    | CredentialConfigurationSupported
    | CredentialOfferFormatV1_0_11
    | CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_13
    | CredentialDefinitionJwtVcJsonV1_0_13
    | JsonLdIssuerCredentialDefinition
    | string,
): string[] | undefined {
  if (subject === undefined) {
    return undefined
  } else if (typeof subject === 'string') {
    return [subject]
  } else if ('credential_definition' in subject) {
    return getTypesFromObject(
      subject.credential_definition as
        | CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_13
        | CredentialDefinitionJwtVcJsonV1_0_13
        | JsonLdIssuerCredentialDefinition,
    )
  } else if ('types' in subject && subject.types) {
    return Array.isArray(subject.types) ? subject.types : [subject.types as string]
  } else if ('type' in subject && subject.type) {
    return Array.isArray(subject.type) ? subject.type : [subject.type as string]
  } else if ('vct' in subject && subject.vct) {
    return [subject.vct as string]
  } else if ('doctype' in subject && subject.doctype) {
    return [subject.doctype as string]
  }
  VCI_LOG_COMMON.warning('Could not deduce credential types. Probably a failure down the line will happen!')
  return undefined
}

export function getTypesFromCredentialOffer(
  offer: UniformCredentialOfferRequest | CredentialOfferPayload | UniformCredentialOfferPayload,
  opts?: { configIdAsType?: boolean },
): Array<Array<string>> | undefined {
  const { configIdAsType = false } = { ...opts }
  if ('credentials' in offer && Array.isArray(offer.credentials)) {
    return offer.credentials.map((cred) => getTypesFromObject(cred)).filter((cred): cred is string[] => cred !== undefined)
  } else if (configIdAsType && 'credential_configuration_ids' in offer && Array.isArray(offer.credential_configuration_ids)) {
    return offer.credential_configuration_ids.map((id) => [id])
  } else if ('credential_offer' in offer && offer.credential_offer) {
    return getTypesFromCredentialOffer(offer.credential_offer, opts)
  } else if ('credential_type' in offer && offer.credential_type) {
    if (typeof offer.credential_type === 'string') {
      return [[offer.credential_type]]
    } else if (Array.isArray(offer.credential_type)) {
      return [offer.credential_type]
    }
  }
  VCI_LOG_COMMON.warning('Could not deduce credential types from offer. Probably a failure down the line will happen!')
  return undefined
}

export function getTypesFromAuthorizationDetails(authDetails: AuthorizationDetails, opts?: { configIdAsType?: boolean }): string[] | undefined {
  const { configIdAsType = false } = { ...opts }
  if (typeof authDetails === 'string') {
    return [authDetails]
  } else if ('types' in authDetails && Array.isArray(authDetails.types)) {
    return authDetails.types
  } else if (configIdAsType && authDetails.credential_configuration_id) {
    return [authDetails.credential_configuration_id]
  }

  return undefined
}

export function getTypesFromCredentialSupported(
  credentialSupported: CredentialConfigurationSupported,
  opts?: { filterVerifiableCredential: boolean },
) {
  let types: string[] = []
  if (
    credentialSupported.format === 'jwt_vc_json' ||
    credentialSupported.format === 'jwt_vc' ||
    credentialSupported.format === 'jwt_vc_json-ld' ||
    credentialSupported.format === 'ldp_vc'
  ) {
    types = getTypesFromObject(credentialSupported) ?? []
  } else if (credentialSupported.format === 'vc+sd-jwt') {
    types = [credentialSupported.vct]
  } else if (credentialSupported.format === 'mso_mdoc') {
    types = [credentialSupported.doctype]
  }

  if (!types || types.length === 0) {
    throw Error('Could not deduce types from credential supported')
  }
  if (opts?.filterVerifiableCredential) {
    return types.filter((type) => type !== 'VerifiableCredential')
  }
  return types
}
