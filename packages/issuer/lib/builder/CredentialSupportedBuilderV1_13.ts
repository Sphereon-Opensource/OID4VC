import {
  CredentialsSupportedDisplay,
  CredentialSupported,
  isFormat,
  isNotFormat,
  IssuerCredentialSubject,
  IssuerCredentialSubjectDisplay,
  OID4VCICredentialFormat,
  TokenErrorResponse,
} from '@sphereon/oid4vci-common'

export class CredentialSupportedBuilderV1_13 {
  format?: OID4VCICredentialFormat
  id?: string
  types?: string[]
  cryptographicBindingMethodsSupported?: ('jwk' | 'cose_key' | 'did' | string)[]
  cryptographicSuitesSupported?: ('jwt_vc' | 'ldp_vc' | string)[]
  display?: CredentialsSupportedDisplay[]
  credentialSubject?: IssuerCredentialSubject

  withFormat(credentialFormat: OID4VCICredentialFormat): CredentialSupportedBuilderV1_13 {
    this.format = credentialFormat
    return this
  }

  withId(id: string): CredentialSupportedBuilderV1_13 {
    this.id = id
    return this
  }

  addTypes(type: string | string[]): CredentialSupportedBuilderV1_13 {
    if (!Array.isArray(type)) {
      this.types = this.types ? [...this.types, type] : [type]
    } else {
      this.cryptographicBindingMethodsSupported = this.cryptographicBindingMethodsSupported
        ? [...this.cryptographicBindingMethodsSupported, ...type]
        : type
    }
    return this
  }

  withTypes(type: string | string[]): CredentialSupportedBuilderV1_13 {
    if (this.format === 'vc+sd-jwt' && Array.isArray(type) && type.length > 1) {
      throw new Error('Only one type is allowed for vc+sd-jwt')
    }
    this.types = Array.isArray(type) ? type : [type]
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

  addCryptographicSuitesSupported(suit: string | string[]): CredentialSupportedBuilderV1_13 {
    if (!Array.isArray(suit)) {
      this.cryptographicSuitesSupported = this.cryptographicSuitesSupported ? [...this.cryptographicSuitesSupported, suit] : [suit]
    } else {
      this.cryptographicSuitesSupported = this.cryptographicSuitesSupported ? [...this.cryptographicSuitesSupported, ...suit] : suit
    }
    return this
  }

  withCryptographicSuitesSupported(suit: string | string[]): CredentialSupportedBuilderV1_13 {
    this.cryptographicSuitesSupported = Array.isArray(suit) ? suit : [suit]
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

  withCredentialSubjectDisplay(credentialSubject: IssuerCredentialSubject) {
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

  public build(): CredentialSupported {
    if (!this.format) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    const credentialSupported: Partial<CredentialSupported> = {
      format: this.format,
    }
    if (!this.types) {
      throw new Error('types are required')
    }

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
    }

    if (this.cryptographicSuitesSupported) {
      credentialSupported.cryptographic_suites_supported = this.cryptographicSuitesSupported
    }
    if (this.cryptographicBindingMethodsSupported) {
      credentialSupported.cryptographic_binding_methods_supported = this.cryptographicBindingMethodsSupported
    }
    if (this.id) {
      credentialSupported.id = this.id
    }
    if (this.display) {
      credentialSupported.display = this.display
    }
    return credentialSupported as CredentialSupported
  }
}
