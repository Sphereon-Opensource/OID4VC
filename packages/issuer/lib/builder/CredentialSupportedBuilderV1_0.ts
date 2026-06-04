import {
  ClaimsDescriptionV1_0,
  CredentialConfigurationSupportedV1_0,
  CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15,
  CredentialDefinitionJwtVcJsonV1_0_15,
  CredentialsSupportedDisplay,
  KeyProofType,
  OID4VCICredentialFormat,
  ProofType,
  ProofTypesSupportedV1_0,
  TokenErrorResponse,
} from '@sphereon/oid4vci-common'

export class CredentialSupportedBuilderV1_0 {
  format?: OID4VCICredentialFormat
  scope?: string
  credentialName?: string
  credentialDefinition?: CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15 | CredentialDefinitionJwtVcJsonV1_0_15
  cryptographicBindingMethodsSupported?: ('jwk' | 'cose_key' | 'did' | string)[]
  cryptographicSuitesSupported?: string[] // 1.0 final: replaces credential_signing_alg_values_supported
  proofTypesSupported?: ProofTypesSupportedV1_0
  display?: CredentialsSupportedDisplay[]
  claims?: ClaimsDescriptionV1_0[]
  vct?: string
  doctype?: string

  withFormat(credentialFormat: OID4VCICredentialFormat): CredentialSupportedBuilderV1_0 {
    this.format = credentialFormat
    return this
  }

  withCredentialName(credentialName: string): CredentialSupportedBuilderV1_0 {
    this.credentialName = credentialName
    return this
  }

  withCredentialDefinition(
    credentialDefinition: CredentialDefinitionJwtVcJsonLdAndLdpVcV1_0_15 | CredentialDefinitionJwtVcJsonV1_0_15,
  ): CredentialSupportedBuilderV1_0 {
    if (!credentialDefinition.type) {
      throw new Error('credentialDefinition should contain a type array')
    }
    this.credentialDefinition = credentialDefinition
    return this
  }

  withScope(scope: string): CredentialSupportedBuilderV1_0 {
    this.scope = scope
    return this
  }

  withVct(vct: string): CredentialSupportedBuilderV1_0 {
    this.vct = vct
    return this
  }

  withDoctype(doctype: string): CredentialSupportedBuilderV1_0 {
    this.doctype = doctype
    return this
  }

  addCryptographicBindingMethod(method: string | string[]): CredentialSupportedBuilderV1_0 {
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

  withCryptographicBindingMethod(method: string | string[]): CredentialSupportedBuilderV1_0 {
    this.cryptographicBindingMethodsSupported = Array.isArray(method) ? method : [method]
    return this
  }

  // 1.0 final: uses cryptographic_suites_supported instead of credential_signing_alg_values_supported
  addCryptographicSuitesSupported(suites: string | string[]): CredentialSupportedBuilderV1_0 {
    if (!Array.isArray(suites)) {
      this.cryptographicSuitesSupported = this.cryptographicSuitesSupported ? [...this.cryptographicSuitesSupported, suites] : [suites]
    } else {
      this.cryptographicSuitesSupported = this.cryptographicSuitesSupported ? [...this.cryptographicSuitesSupported, ...suites] : suites
    }
    return this
  }

  withCryptographicSuitesSupported(suites: string | string[]): CredentialSupportedBuilderV1_0 {
    this.cryptographicSuitesSupported = Array.isArray(suites) ? suites : [suites]
    return this
  }

  addProofTypesSupported(keyProofType: KeyProofType, proofType: ProofType): CredentialSupportedBuilderV1_0 {
    if (!this.proofTypesSupported) {
      this.proofTypesSupported = {}
    }
    this.proofTypesSupported[keyProofType] = proofType
    return this
  }

  withProofTypesSupported(proofTypesSupported: ProofTypesSupportedV1_0): CredentialSupportedBuilderV1_0 {
    this.proofTypesSupported = proofTypesSupported
    return this
  }

  addCredentialSupportedDisplay(credentialDisplay: CredentialsSupportedDisplay | CredentialsSupportedDisplay[]): CredentialSupportedBuilderV1_0 {
    if (!Array.isArray(credentialDisplay)) {
      this.display = this.display ? [...this.display, credentialDisplay] : [credentialDisplay]
    } else {
      this.display = this.display ? [...this.display, ...credentialDisplay] : credentialDisplay
    }
    return this
  }

  withCredentialSupportedDisplay(credentialDisplay: CredentialsSupportedDisplay | CredentialsSupportedDisplay[]): CredentialSupportedBuilderV1_0 {
    this.display = Array.isArray(credentialDisplay) ? credentialDisplay : [credentialDisplay]
    return this
  }

  withClaims(claims: ClaimsDescriptionV1_0[]): CredentialSupportedBuilderV1_0 {
    this.claims = claims
    return this
  }

  addClaim(claim: ClaimsDescriptionV1_0): CredentialSupportedBuilderV1_0 {
    if (!this.claims) {
      this.claims = []
    }
    this.claims.push(claim)
    return this
  }

  public build(): Record<string, CredentialConfigurationSupportedV1_0> {
    if (!this.format) {
      throw new Error(TokenErrorResponse.invalid_request)
    }

    const credentialSupported: CredentialConfigurationSupportedV1_0 = {
      format: this.format,
    } as CredentialConfigurationSupportedV1_0

    if (!this.credentialName) {
      throw new Error('A unique credential name is required')
    }

    if (this.format === 'dc+sd-jwt' || this.format === 'vc+sd-jwt') {
      if (!this.vct) {
        throw new Error('vct is required for sd-jwt format')
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
      ;(credentialSupported as any).credential_definition = this.credentialDefinition
    }

    if (this.scope) {
      credentialSupported.scope = this.scope
    }
    // 1.0 final: uses cryptographic_suites_supported
    if (this.cryptographicSuitesSupported) {
      credentialSupported.cryptographic_suites_supported = this.cryptographicSuitesSupported
    }
    if (this.cryptographicBindingMethodsSupported) {
      credentialSupported.cryptographic_binding_methods_supported = this.cryptographicBindingMethodsSupported
    }
    if (this.display) {
      credentialSupported.display = this.display
    }
    if (this.claims) {
      ;(credentialSupported as any).claims = this.claims
    }

    const supportedConfiguration: Record<string, CredentialConfigurationSupportedV1_0> = {}
    supportedConfiguration[this.credentialName] = credentialSupported as CredentialConfigurationSupportedV1_0

    return supportedConfiguration
  }
}
