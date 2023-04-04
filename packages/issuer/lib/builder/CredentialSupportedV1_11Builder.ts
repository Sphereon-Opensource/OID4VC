import {
  CredentialFormatEnum,
  CredentialIssuerMetadataSupportedCredentials,
  Display,
  IssuerCredentialSubject,
  IssuerCredentialSubjectDisplay,
  SupportedCredentialIssuerMetadataJwtVcJson,
  SupportedCredentialIssuerMetadataJwtVcJsonLdAndLdpVc,
  TokenErrorResponse,
} from '@sphereon/openid4vci-common'

export class CredentialSupportedV1_11Builder {
  format?: CredentialFormatEnum
  id?: string
  types?: string[]
  cryptographicBindingMethodsSupported?: ('jwk' | 'cose_key' | 'did' | string)[]
  cryptographicSuitesSupported?: ('jwt_vc' | 'ldp_vc' | string)[]
  display?: Display[]
  credentialSubject?: IssuerCredentialSubject

  withFormat(credentialFormat: CredentialFormatEnum): CredentialSupportedV1_11Builder {
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

  withCredentialDisplay(credentialDisplay: Display | Display[]): CredentialSupportedV1_11Builder {
    if (!Array.isArray(credentialDisplay)) {
      this.display = this.display ? [...this.display, credentialDisplay] : [credentialDisplay]
    } else {
      this.display = this.display ? [...this.display, ...credentialDisplay] : credentialDisplay
    }
    return this
  }

  withIssuerCredentialSubjectDisplay(
    subjectProperty: string,
    issuerCredentialSubjectDisplay: IssuerCredentialSubjectDisplay
  ): CredentialSupportedV1_11Builder {
    if (!this.credentialSubject) {
      this.credentialSubject = {}
    }
    this.credentialSubject[subjectProperty] = issuerCredentialSubjectDisplay
    return this
  }

  public build(): CredentialIssuerMetadataSupportedCredentials {
    if (!this.format) {
      throw new Error(TokenErrorResponse.invalid_request)
    }
    const credentialSupported: CredentialIssuerMetadataSupportedCredentials = {
      format: this.format,
    }
    if (this.credentialSubject) {
      ;(credentialSupported as SupportedCredentialIssuerMetadataJwtVcJsonLdAndLdpVc | SupportedCredentialIssuerMetadataJwtVcJson).credentialSubject =
        this.credentialSubject
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
      ;(credentialSupported as SupportedCredentialIssuerMetadataJwtVcJsonLdAndLdpVc | SupportedCredentialIssuerMetadataJwtVcJson).display =
        this.display
    }
    return credentialSupported
  }
}
