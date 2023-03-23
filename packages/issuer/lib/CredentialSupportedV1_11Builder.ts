import {
  CredentialFormat,
  ICredentialDisplay,
  ICredentialSupportedV1_11,
  IIssuerCredentialSubjectDisplayNameAndLocale,
  IIssuerCredentialSubjectV1_11,
  invalid_request,
} from '@sphereon/openid4vci-common'

export class CredentialSupportedV1_11Builder {
  format?: CredentialFormat
  id?: string
  types?: string[]
  cryptographicBindingMethodsSupported?: ('jwk' | 'cose_key' | 'did' | string)[]
  cryptographicSuitesSupported?: ('jwt_vc' | 'ldp_vc' | string)[]
  display?: ICredentialDisplay[]
  credentialSubject?: IIssuerCredentialSubjectV1_11

  withFormat(credentialFormat: CredentialFormat): CredentialSupportedV1_11Builder {
    this.format = credentialFormat
    return this
  }

  withId(id: string): CredentialSupportedV1_11Builder {
    this.id = id
    return this
  }

  withTypes(type: string | string[]): CredentialSupportedV1_11Builder {
    if (!Array.isArray(type)) {
      this.types = this.types ? [...this.types, type] : [type]
    } else {
      this.cryptographicBindingMethodsSupported = this.cryptographicBindingMethodsSupported
        ? [...this.cryptographicBindingMethodsSupported, ...type]
        : type
    }
    return this
  }
  withCryptographicBindingMethod(method: string | string[]): CredentialSupportedV1_11Builder {
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

  withCryptographicSuitesSupported(suit: string | string[]): CredentialSupportedV1_11Builder {
    if (!Array.isArray(suit)) {
      this.cryptographicSuitesSupported = this.cryptographicSuitesSupported ? [...this.cryptographicSuitesSupported, suit] : [suit]
    } else {
      this.cryptographicSuitesSupported = this.cryptographicSuitesSupported ? [...this.cryptographicSuitesSupported, ...suit] : suit
    }
    return this
  }

  withCredentialDisplay(credentialDisplay: ICredentialDisplay | ICredentialDisplay[]): CredentialSupportedV1_11Builder {
    if (!Array.isArray(credentialDisplay)) {
      this.display = this.display ? [...this.display, credentialDisplay] : [credentialDisplay]
    } else {
      this.display = this.display ? [...this.display, ...credentialDisplay] : credentialDisplay
    }
    return this
  }

  withIssuerCredentialSubjectDisplay(
    subjectProperty: string,
    credentialSubjectDisplayNameAndLocale: IIssuerCredentialSubjectDisplayNameAndLocale | IIssuerCredentialSubjectDisplayNameAndLocale[]
  ): CredentialSupportedV1_11Builder {
    if (!this.credentialSubject) {
      this.credentialSubject = {}
    }
    if (!Array.isArray(credentialSubjectDisplayNameAndLocale)) {
      this.credentialSubject[subjectProperty] = this.credentialSubject[subjectProperty]
        ? {
            display: [...this.credentialSubject[subjectProperty].display, credentialSubjectDisplayNameAndLocale],
          }
        : {
            display: [credentialSubjectDisplayNameAndLocale],
          }
    } else {
      this.credentialSubject[subjectProperty] = this.credentialSubject[subjectProperty]
        ? { display: [...this.credentialSubject[subjectProperty].display, ...credentialSubjectDisplayNameAndLocale] }
        : { display: credentialSubjectDisplayNameAndLocale }
    }
    return this
  }

  public build(): ICredentialSupportedV1_11 {
    if (!this.format) {
      throw new Error(invalid_request)
    }
    const credentialSupported: ICredentialSupportedV1_11 = {
      format: this.format,
    }
    if (this.credentialSubject) {
      credentialSupported.credentialSubject = this.credentialSubject
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
    return credentialSupported
  }
}
