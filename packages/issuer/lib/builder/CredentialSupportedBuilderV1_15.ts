import {
  ClaimsDescriptionV1_0_15,
  CredentialConfigurationSupportedV1_0_15,
  CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15,
  CredentialDefinitionJwtVcJsonV1_0_15,
  CredentialsSupportedDisplay,
  KeyProofType,
  OID4VCICredentialFormat,
  ProofType,
  ProofTypesSupported,
  TokenErrorResponse
} from '@sphereon/oid4vci-common'

export class CredentialSupportedBuilderV1_15 {
  format?: OID4VCICredentialFormat
  scope?: string
  credentialName?: string
  credentialDefinition?: CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15 | CredentialDefinitionJwtVcJsonV1_0_15
  cryptographicBindingMethodsSupported?: ('jwk' | 'cose_key' | 'did' | string)[]
  credentialSigningAlgValuesSupported?: string[]
  proofTypesSupported?: ProofTypesSupported
  display?: CredentialsSupportedDisplay[]
  claims?: ClaimsDescriptionV1_0_15[] // Changed to use claims path pointers in v15
  vct?: string // For dc+sd-jwt format
  doctype?: string // For mso_mdoc format

  withFormat(credentialFormat: OID4VCICredentialFormat): CredentialSupportedBuilderV1_15 {
    this.format = credentialFormat
    return this
  }

  withCredentialName(credentialName: string): CredentialSupportedBuilderV1_15 {
    this.credentialName = credentialName
    return this
  }

  withCredentialDefinition(
    credentialDefinition: CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15 | CredentialDefinitionJwtVcJsonV1_0_15
  ): CredentialSupportedBuilderV1_15 {
    if (!credentialDefinition.type) {
      throw new Error('credentialDefinition should contain a type array')
    }
    this.credentialDefinition = credentialDefinition
    return this
  }

  withScope(scope: string): CredentialSupportedBuilderV1_15 {
    this.scope = scope
    return this
  }

  // New in v15: VCT support for dc+sd-jwt format
  withVct(vct: string): CredentialSupportedBuilderV1_15 {
    this.vct = vct
    return this
  }

  // New in v15: Doctype support for mso_mdoc format
  withDoctype(doctype: string): CredentialSupportedBuilderV1_15 {
    this.doctype = doctype
    return this
  }

  addCryptographicBindingMethod(method: string | string[]): CredentialSupportedBuilderV1_15 {
    if (!Array.isArray(method)) {
      this.cryptographicBindingMethodsSupported = this.cryptographicBindingMethodsSupported
        ? [...this.cryptographicBindingMethodsSupported, method]
        : [method]
    } else {
      this.cryptographicBindingMethodsSupported = this.cryptographicBindingMethodsSupported
        ? [...this.cryptographicBindingMethodsSupported, ...method]
        : method
    }
    return this
  }

  withCryptographicBindingMethod(method: string | string[]): CredentialSupportedBuilderV1_15 {
    this.cryptographicBindingMethodsSupported = Array.isArray(method) ? method : [method]
    return this
  }

  addCredentialSigningAlgValuesSupported(algValues: string | string[]): CredentialSupportedBuilderV1_15 {
    if (!Array.isArray(algValues)) {
      this.credentialSigningAlgValuesSupported = this.credentialSigningAlgValuesSupported
        ? [...this.credentialSigningAlgValuesSupported, algValues]
        : [algValues]
    } else {
      this.credentialSigningAlgValuesSupported = this.credentialSigningAlgValuesSupported
        ? [...this.credentialSigningAlgValuesSupported, ...algValues]
        : algValues
    }
    return this
  }

  withCredentialSigningAlgValuesSupported(algValues: string | string[]): CredentialSupportedBuilderV1_15 {
    this.credentialSigningAlgValuesSupported = Array.isArray(algValues) ? algValues : [algValues]
    return this
  }

  addProofTypesSupported(keyProofType: KeyProofType, proofType: ProofType): CredentialSupportedBuilderV1_15 {
    if (!this.proofTypesSupported) {
      this.proofTypesSupported = {}
    }
    this.proofTypesSupported[keyProofType] = proofType
    return this
  }

  withProofTypesSupported(proofTypesSupported: ProofTypesSupported): CredentialSupportedBuilderV1_15 {
    this.proofTypesSupported = proofTypesSupported
    return this
  }

  addCredentialSupportedDisplay(credentialDisplay: CredentialsSupportedDisplay | CredentialsSupportedDisplay[]): CredentialSupportedBuilderV1_15 {
    if (!Array.isArray(credentialDisplay)) {
      this.display = this.display ? [...this.display, credentialDisplay] : [credentialDisplay]
    } else {
      this.display = this.display ? [...this.display, ...credentialDisplay] : credentialDisplay
    }
    return this
  }

  withCredentialSupportedDisplay(credentialDisplay: CredentialsSupportedDisplay | CredentialsSupportedDisplay[]): CredentialSupportedBuilderV1_15 {
    this.display = Array.isArray(credentialDisplay) ? credentialDisplay : [credentialDisplay]
    return this
  }

  // New in v15: Claims description using path pointers
  withClaims(claims: ClaimsDescriptionV1_0_15[]): CredentialSupportedBuilderV1_15 {
    this.claims = claims
    return this
  }

  addClaim(claim: ClaimsDescriptionV1_0_15): CredentialSupportedBuilderV1_15 {
    if (!this.claims) {
      this.claims = []
    }
    this.claims.push(claim)
    return this
  }

  public build(): Record<string, CredentialConfigurationSupportedV1_0_15> {
    if (!this.format) {
      throw new Error(TokenErrorResponse.invalid_request)
    }

    const credentialSupported: CredentialConfigurationSupportedV1_0_15 = {
      format: this.format
    } as CredentialConfigurationSupportedV1_0_15

    if (!this.credentialName) {
      throw new Error('A unique credential name is required')
    }

    // Format-specific handling for v15
    if (this.format === 'dc+sd-jwt') {
      if (!this.vct) {
        throw new Error('vct is required for dc+sd-jwt format')
      }
      ;(credentialSupported as any).vct = this.vct
    } else if (this.format === 'mso_mdoc') {
      if (!this.doctype) {
        throw new Error('doctype is required for mso_mdoc format')
      }
      ;(credentialSupported as any).doctype = this.doctype
    } else {
      if (!this.credentialDefinition) {
        throw new Error('credentialDefinition is required')
      }
      credentialSupported.credential_definition = this.credentialDefinition
    }

    if (this.scope) {
      credentialSupported.scope = this.scope
    }
    if (this.credentialSigningAlgValuesSupported) {
      credentialSupported.credential_signing_alg_values_supported = this.credentialSigningAlgValuesSupported
    }
    if (this.cryptographicBindingMethodsSupported) {
      credentialSupported.cryptographic_binding_methods_supported = this.cryptographicBindingMethodsSupported
    }
    if (this.display) {
      credentialSupported.display = this.display
    }
    if (this.claims) {
      (credentialSupported as any).claims = this.claims
    }

    const supportedConfiguration: Record<string, CredentialConfigurationSupportedV1_0_15> = {}
    supportedConfiguration[this.credentialName] = credentialSupported as CredentialConfigurationSupportedV1_0_15

    return supportedConfiguration
  }
}