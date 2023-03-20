import { W3CVerifiableCredential } from '@sphereon/ssi-types'

export interface ICredentialIssuerMetadataParametersV1_11 {
  credential_issuer: string
  authorization_server?: string
  credential_endpoint: string
  batch_credential_endpoint?: string
  credentials_supported: ICredentialSupportedV1_11[]
  display?: IIssuerDisplay[]
}

export interface IIssuerDisplay {
  name?: string
  locale?: string
}

export interface ICredentialSupportedV1_11 {
  format: CredentialFormat
  id?: string
  //todo find a better way of handling the general string. the general string is for supporting various did methods here: did:web, did:example, ....
  cryptographic_binding_methods_supported?: ('jwk' | 'cose_key' | 'did' | string)[]
  cryptographic_suites_supported?: ('jwt_vc' | 'ldp_vc' | string)[]
  display?: ICredentialDisplay[]
  credentialSubject?: IIssuerCredentialSubject
}

export interface IIssuerCredentialSubject {
  [x: string]: IIssuerCredentialSubjectDisplay
}

export interface IIssuerCredentialSubjectDisplay {
  display: IIssuerCredentialSubjectDisplayNameAndLocale[]
}

export interface IIssuerCredentialSubjectDisplayNameAndLocale {
  name: string
  locale?: string
}

export interface ICredentialDisplay {
  name: string
  locale?: string
  logo?: ICredentialLogo
  description?: string
  // should be according to https://www.w3.org/TR/css-color-3/
  background_color?: string
  text_color?: string
}

export interface ICredentialLogo {
  url?: string
  alt_text?: string
}

export type CredentialFormat = 'jwt_vc_json' | 'jwt_vc_json-ld' | 'ldp_vc' | 'mso_mdoc'

export interface IIssueCredentialRequest {
  format: CredentialFormat
  proof: ICredentialRequestProof
  types: string[]
}

export interface ICredentialRequestProof {
  proof_type: 'jwt' | string
  jwt?: string
}

export interface ICredentialSuccessResponse {
  format: CredentialFormat
  credential?: W3CVerifiableCredential
  acceptance_token?: string
  c_nonce?: string
  c_nonce_expires_in?: number
}
