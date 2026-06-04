import { CredentialConfigurationSupportedV1_0_15, VCI_LOG_COMMON } from '../index'
import {
  AuthorizationServerMetadata,
  CredentialConfigurationSupported,
  CredentialIssuerMetadata,
  IssuerMetadata,
  MetadataDisplay,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
} from '../types'
import { getTypesFromObject, isW3cCredentialSupported } from './TypeConversionUtils'

export function getSupportedCredentials(opts?: {
  issuerMetadata?: CredentialIssuerMetadata | IssuerMetadata
  version: OpenId4VCIVersion
  types?: string[][]
  format?: OID4VCICredentialFormat | string | (OID4VCICredentialFormat | string)[]
}): Record<string, CredentialConfigurationSupportedV1_0_15> | Array<CredentialConfigurationSupported> {
  const { version = OpenId4VCIVersion.VER_1_0_15, types } = opts ?? {}
  if (types && Array.isArray(types)) {
    return types
      .map((typeSet) => {
        return getSupportedCredential({ ...opts, version, types: typeSet })
      })
      .reduce(
        (acc, result) => {
          Object.assign(acc, result)
          return acc
        },
        {} as Record<string, CredentialConfigurationSupportedV1_0_15>,
      )
  }

  return getSupportedCredential(opts ? { ...opts, types: undefined } : undefined)
}

export function determineVersionsFromIssuerMetadata(issuerMetadata: CredentialIssuerMetadata | IssuerMetadata): Array<OpenId4VCIVersion> {
  const versions = new Set<OpenId4VCIVersion>()
  if ('credential_configurations_supported' in issuerMetadata) {
    // detect 1.0 final vs draft 15 based on metadata field differences
    let is1_0Final = false

    // 1.0 final uses batch_credential_issuance_supported (boolean) instead of batch_credential_issuance (object)
    if ('batch_credential_issuance_supported' in issuerMetadata && typeof (issuerMetadata as any).batch_credential_issuance_supported === 'boolean') {
      is1_0Final = true
    }

    // 1.0 final has credential_issuer_public_key
    if ('credential_issuer_public_key' in issuerMetadata) {
      is1_0Final = true
    }

    // Check credential configs for 1.0-specific fields
    if (!is1_0Final) {
      const configs = issuerMetadata.credential_configurations_supported
      if (configs) {
        for (const config of Object.values(configs)) {
          // 1.0 final uses cryptographic_suites_supported instead of credential_signing_alg_values_supported
          if ('cryptographic_suites_supported' in config) {
            is1_0Final = true
            break
          }
          // 1.0 final uses di_vp proof type instead of ldp_vp
          if (config.proof_types_supported && 'di_vp' in config.proof_types_supported) {
            is1_0Final = true
            break
          }
        }
      }
    }

    if (is1_0Final) {
      versions.add(OpenId4VCIVersion.VER_1_0)
    } else {
      // Default to 1.0 final if ambiguous (since both versions share credential_configurations_supported)
      // but if batch_credential_issuance object exists, it's clearly draft 15
      if ('batch_credential_issuance' in issuerMetadata && typeof (issuerMetadata as any).batch_credential_issuance === 'object') {
        versions.add(OpenId4VCIVersion.VER_1_0_15)
      } else {
        // Ambiguous - default to 1.0 final as the latest version
        versions.add(OpenId4VCIVersion.VER_1_0)
      }
    }
  }

  if (versions.size === 0) {
    versions.add(OpenId4VCIVersion.VER_UNKNOWN)
  }

  return Array.from(versions).sort().reverse() // highest version first
}

export function getSupportedCredential(opts?: {
  issuerMetadata?: CredentialIssuerMetadata | IssuerMetadata
  version: OpenId4VCIVersion
  types?: string | string[]
  format?: OID4VCICredentialFormat | string | (OID4VCICredentialFormat | string)[]
}): Record<string, CredentialConfigurationSupportedV1_0_15> | Array<CredentialConfigurationSupported> {
  const { issuerMetadata, types, format, version = OpenId4VCIVersion.VER_1_0_15 } = opts ?? {}

  let credentialConfigurationsV15: Record<string, CredentialConfigurationSupportedV1_0_15> | undefined = undefined

  // Check if we have v15 credential_configurations_supported
  if (issuerMetadata?.credential_configurations_supported && version >= OpenId4VCIVersion.VER_1_0_15) {
    credentialConfigurationsV15 = issuerMetadata.credential_configurations_supported as Record<string, CredentialConfigurationSupportedV1_0_15>
  }
  if (!issuerMetadata || (!issuerMetadata.credential_configurations_supported && !issuerMetadata.credentials_supported)) {
    VCI_LOG_COMMON.warning(`No credential issuer metadata or supported credentials found for issuer`)
    if (version >= OpenId4VCIVersion.VER_1_0_15) {
      return credentialConfigurationsV15 ?? {}
    } else {
      return []
    }
  }

  const normalizedTypes: string[] = Array.isArray(types) ? types : types ? [types] : []
  const normalizedFormats: string[] = Array.isArray(format) ? format : format ? [format] : []

  function filterMatchingConfig(config: CredentialConfigurationSupported): CredentialConfigurationSupported | undefined {
    let isTypeMatch = normalizedTypes.length === 0
    const types = getTypesFromObject(config)
    if (!isTypeMatch) {
      if (normalizedTypes.length === 1 && config.id === normalizedTypes[0]) {
        isTypeMatch = true
      } else if (types) {
        isTypeMatch = normalizedTypes.every((type) => types.includes(type))
      } else {
        // Type guard to check if credential_definition has the expected structure
        const hasValidCredentialDefinition =
          isW3cCredentialSupported(config) &&
          'credential_definition' in config &&
          config.credential_definition &&
          typeof config.credential_definition === 'object' &&
          'type' in config.credential_definition &&
          Array.isArray(config.credential_definition.type)

        if (hasValidCredentialDefinition) {
          const credDef = config.credential_definition as { type: string[] }
          isTypeMatch = normalizedTypes.every((type) => credDef.type.includes(type))
        } else if (isW3cCredentialSupported(config) && 'type' in config && Array.isArray(config.type)) {
          isTypeMatch = normalizedTypes.every((type) => (config.type as string[]).includes(type))
        } else if (isW3cCredentialSupported(config) && 'types' in config && Array.isArray(config.types)) {
          isTypeMatch = normalizedTypes.every((type) => (config.types as string[]).includes(type))
        }
      }
    }

    const isFormatMatch = normalizedFormats.length === 0 || normalizedFormats.includes(config.format)

    return isTypeMatch && isFormatMatch ? config : undefined
  }

  if (credentialConfigurationsV15) {
    return Object.entries(credentialConfigurationsV15).reduce(
      (filteredConfigs, [id, config]) => {
        if (filterMatchingConfig(config)) {
          filteredConfigs[id] = config
          // Added to enable support < 13. We basically assign the id
          if (!config.id) {
            config.id = id
          }
        }
        return filteredConfigs
      },
      {} as Record<string, CredentialConfigurationSupportedV1_0_15>,
    )
  }

  // Handle legacy credentials_supported for older versions
  if (issuerMetadata.credentials_supported && Array.isArray(issuerMetadata.credentials_supported)) {
    return issuerMetadata.credentials_supported.filter(filterMatchingConfig) as Array<CredentialConfigurationSupported>
  }

  return version >= OpenId4VCIVersion.VER_1_0_15 ? {} : []
}

export function getIssuerDisplays(
  metadata: CredentialIssuerMetadata | IssuerMetadata,
  opts?: {
    prefLocales: string[]
  },
): MetadataDisplay[] {
  const matchedDisplays =
    metadata.display?.filter(
      (item: MetadataDisplay) =>
        !opts?.prefLocales || opts.prefLocales.length === 0 || (item.locale && opts.prefLocales.includes(item.locale)) || !item.locale,
    ) ?? []
  return matchedDisplays.sort((item: MetadataDisplay) => (item.locale ? (opts?.prefLocales.indexOf(item.locale) ?? 1) : Number.MAX_VALUE))
}

/**
 * TODO check again when WAL-617 is done to replace how we get the issuer name.
 */
export function getIssuerName(
  url: string,
  credentialIssuerMetadata?: Partial<AuthorizationServerMetadata> & (CredentialIssuerMetadata | IssuerMetadata),
): string {
  if (credentialIssuerMetadata) {
    const displays: Array<MetadataDisplay> = credentialIssuerMetadata ? getIssuerDisplays(credentialIssuerMetadata) : []
    for (const display of displays) {
      if (display.name) {
        return display.name
      }
    }
  }
  return url
}
