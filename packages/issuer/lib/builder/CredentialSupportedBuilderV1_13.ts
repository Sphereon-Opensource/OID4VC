import {
  CredentialConfigurationSupportedV1_0_13,
  CredentialDefinitionV1_0_13,
  CredentialsSupportedDisplay,
  IssuerCredentialSubject,
  IssuerCredentialSubjectDisplay,
  KeyProofType,
  OID4VCICredentialFormat,
  ProofType,
  TokenErrorResponse,
} from '@sphereon/oid4vci-common'

export class CredentialSupportedBuilderV1_13 {
  format?: OID4VCICredentialFormat
  scope?: string
  credentialName?: string
  credentialDefinition?: CredentialDefinitionV1_0_13
  cryptographicBindingMethodsSupported?: ('jwk' | 'cose_key' | 'did' | string)[]
  credentialSigningAlgValuesSupported?: string[]
  proofTypesSupported?: Record<KeyProofType, ProofType>
  display?: CredentialsSupportedDisplay[]
  credentialSubject?: IssuerCredentialSubject

  withFormat(credentialFormat: OID4VCICredentialFormat): CredentialSupportedBuilderV1_13 {
    this.format = credentialFormat
    return this
  }

  withCredentialName(credentialName: string): CredentialSupportedBuilderV1_13 {
    this.credentialName = credentialName
    return this
  }

  withCredentialDefinition(credentialDefinition: CredentialDefinitionV1_0_13): CredentialSupportedBuilderV1_13 {
    if (!credentialDefinition.type) {
      throw new Error('credentialDefinition should contain a type array')
    }
    this.credentialDefinition = credentialDefinition
    return this
  }

  withScope(scope: string): CredentialSupportedBuilderV1_13 {
    this.scope = scope
    return this
  }
  addCryptographicBindingMethod(method: string | string[]): CredentialSupportedBuilderV1_13 {
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

  withCryptographicBindingMethod(method: string | string[]): CredentialSupportedBuilderV1_13 {
    this.cryptographicBindingMethodsSupported = Array.isArray(method) ? method : [method]
    return this
  }

  addCredentialSigningAlgValuesSupported(algValues: string | string[]): CredentialSupportedBuilderV1_13 {
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

  withCredentialSigningAlgValuesSupported(algValues: string | string[]): CredentialSupportedBuilderV1_13 {
    this.credentialSigningAlgValuesSupported = Array.isArray(algValues) ? algValues : [algValues]
    return this
  }

  addProofTypesSupported(keyProofType: KeyProofType, proofType: ProofType): CredentialSupportedBuilderV1_13 {
    if (!this.proofTypesSupported) {
      this.proofTypesSupported = {} as Record<KeyProofType, ProofType>
    }
    this.proofTypesSupported[keyProofType] = proofType
    return this
  }

  withProofTypesSupported(proofTypesSupported: Record<KeyProofType, ProofType>): CredentialSupportedBuilderV1_13 {
    this.proofTypesSupported = proofTypesSupported
    return this
  }

  addCredentialSupportedDisplay(credentialDisplay: CredentialsSupportedDisplay | CredentialsSupportedDisplay[]): CredentialSupportedBuilderV1_13 {
    if (!Array.isArray(credentialDisplay)) {
      this.display = this.display ? [...this.display, credentialDisplay] : [credentialDisplay]
    } else {
      this.display = this.display ? [...this.display, ...credentialDisplay] : credentialDisplay
    }
    return this
  }

  withCredentialSupportedDisplay(credentialDisplay: CredentialsSupportedDisplay | CredentialsSupportedDisplay[]): CredentialSupportedBuilderV1_13 {
    this.display = Array.isArray(credentialDisplay) ? credentialDisplay : [credentialDisplay]
    return this
  }

  withCredentialSubject(credentialSubject: IssuerCredentialSubject) {
    this.credentialSubject = credentialSubject
    return this
  }

  addCredentialSubjectPropertyDisplay(
    subjectProperty: string,
    issuerCredentialSubjectDisplay: IssuerCredentialSubjectDisplay,
  ): CredentialSupportedBuilderV1_13 {
    if (!this.credentialSubject) {
      this.credentialSubject = {}
    }
    this.credentialSubject[subjectProperty] = issuerCredentialSubjectDisplay
    return this
  }

  public build(): Record<string, CredentialConfigurationSupportedV1_0_13> {
    if (!this.format) {
      throw new Error(TokenErrorResponse.invalid_request)
    }

    const credentialSupported: CredentialConfigurationSupportedV1_0_13 = {
      format: this.format,
    } as CredentialConfigurationSupportedV1_0_13

    if (!this.credentialDefinition) {
      throw new Error('credentialDefinition is required')
    }
    credentialSupported.credential_definition = this.credentialDefinition
    if (this.scope) {
      credentialSupported.scope = this.scope
    }
    if (!this.credentialName) {
      throw new Error('A unique credential name is required')
    }
    //TODO: right now commented out all the special handlings for sd-jwt
    /*
    // SdJwtVc has a different format
    if (isFormat(credentialSupported, 'vc+sd-jwt')) {
      if (this.types.length > 1) {
        throw new Error('Only one type is allowed for vc+sd-jwt')
      }
      credentialSupported.vct = this.types[0]
    }
    // And else would work here, but this way we get the correct typing
    else if (isNotFormat(credentialSupported, 'vc+sd-jwt')) {
      credentialSupported.types = this.types

      if (this.credentialSubject) {
        credentialSupported.credentialSubject = this.credentialSubject
      }
    }*/

    if (this.credentialSigningAlgValuesSupported) {
      credentialSupported.credential_signing_alg_values_supported = this.credentialSigningAlgValuesSupported
    }
    if (this.cryptographicBindingMethodsSupported) {
      credentialSupported.cryptographic_binding_methods_supported = this.cryptographicBindingMethodsSupported
    }
    if (this.display) {
      credentialSupported.display = this.display
    }

    const supportedConfiguration: Record<string, CredentialConfigurationSupportedV1_0_13> = {}
    supportedConfiguration[this.credentialName] = credentialSupported as CredentialConfigurationSupportedV1_0_13

    return supportedConfiguration
  }
}
