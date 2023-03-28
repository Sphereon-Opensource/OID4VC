import { W3CVerifiableCredential } from '@sphereon/ssi-types';

import { OAuth2ASMetadata } from './OAuth2ASMetadata';

export interface CredentialOfferWithBaseURL {
  baseUrl: string;
  credentialIssuerMetadata: ICredentialIssuerMetadataParametersV1_11;
}

export interface ICredentialIssuerMetadataParametersV1_11 {
  credential_issuer: string;
  authorization_server?: string;
  credential_endpoint: string;
  batch_credential_endpoint?: string;
  credentials_supported: ICredentialSupportedV1_11[];
  display?: IIssuerDisplay[];
}

export interface IIssuerDisplay {
  name?: string;
  locale?: string;
}

export interface ICredentialSupportedV1_11 {
  format: OpenID4VCICredentialFormatTypes;
  id?: string;
  types?: string[];
  //todo find a better way of handling the general string. the general string is for supporting various did methods here: did:web, did:example, ....
  cryptographic_binding_methods_supported?: ('jwk' | 'cose_key' | 'did' | string)[];
  cryptographic_suites_supported?: ('jwt_vc' | 'ldp_vc' | string)[];
  display?: ICredentialDisplay[];
  credentialSubject?: IIssuerCredentialSubjectV1_11;
}

export interface IIssuerCredentialSubjectV1_11 {
  [x: string]: IIssuerCredentialSubjectDisplayV1_11;
}

export interface IIssuerCredentialSubjectDisplayV1_11 {
  display: IIssuerCredentialSubjectDisplayNameAndLocale[];
}

export interface IIssuerCredentialSubjectDisplayNameAndLocale {
  name: string;
  locale?: string;
}

export interface ICredentialDisplay {
  name: string; //REQUIRED. String value of a display name for the Credential.
  locale?: string; //OPTIONAL. String value that identifies language of this display object represented as language tag values defined in BCP47 [RFC5646]. Multiple display objects may be included for separate languages. There MUST be only one object with the same language identifier.
  logo?: Logo; //A JSON object with information about the logo of the Credential with a following non-exhaustive list of parameters that MAY be included:
  // the following was been misplaced in our previous impl (it was placed in the logo interface) because of missed indentation in the spec. brought these back into CredentialDisplay interface
  description?: string; //OPTIONAL. String value of a description of the Credential.
  background_color?: string; //OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
  text_color?: string; //OPTIONAL. String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure
}

export type CredentialFormat = 'jwt_vc_json' | 'jwt_vc_json-ld' | 'ldp_vc' | 'mso_mdoc';

export interface IIssueCredentialRequest {
  format: OpenID4VCICredentialFormatTypes;
  proof: ICredentialRequestProof;
  types: string[];
}

export interface ICredentialRequestProof {
  proof_type: 'jwt' | string;
  jwt?: string;
}

export interface ICredentialSuccessResponse {
  format: OpenID4VCICredentialFormatTypes;
  credential?: W3CVerifiableCredential;
  acceptance_token?: string;
  c_nonce?: string;
  c_nonce_expires_in?: number;
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2
export interface OpenID4VCIServerMetadata {
  credential_endpoint: string; //REQUIRED. URL of the OP's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  credentials_supported: CredentialsSupported; //REQUIRED. A JSON object containing a list of key value pairs, where the key is a string serving as an abstract identifier of the Credential. This identifier is RECOMMENDED to be collision resistant - it can be globally unique, but does not have to be when naming conflicts are unlikely to arise in a given use case. The value is a JSON object. The JSON object MUST conform to the structure of the Section 11.2.1.
  credential_issuer?: CredentialIssuer; //  A JSON object containing display properties for the Credential issuer.
  token_endpoint?: string; //NON-SPEC compliant, but used by several issuers. URL of the OP's Token Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  authorization_server?: string; //NON-SPEC compliant, but used by some issuers. URL of the AS. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  // TODO: The above authorization_server being used in the wild, serves roughly the same purpose as the below spec compliant endpoint. Look at how to use authorization_server as authorization_endpoint in case it is present
  authorization_endpoint?: string;
}

export type Oauth2ASWithOID4VCIMetadata = OAuth2ASMetadata & OpenID4VCIServerMetadata;

export interface CredentialIssuer {
  display?: IssuerDisplay; //OPTIONAL. An array of objects, where each object contains display properties of a Credential issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-metadata-object
//fixme(sksadjad): I'm assuming this type belongs to 1_09 because it was implemented a while ago, but it's good to investigate it further
export interface CredentialMetadataV1_09 {
  display?: ICredentialDisplay[]; //OPTIONAL. An array of objects, where each object contains display properties of a certain Credential for a certain language. Below is a non-exhaustive list of parameters that MAY be included. Note that the display name of the Credential is obtained from display.name and individual claim names from claims.display.name values.
  formats: Formats; //REQUIRED. A JSON object containing a list of key value pairs, where the key is a string identifying the format of the Credential. Below is a non-exhaustive list of valid key values defined by this specification:
  claims?: Claims; //REQUIRED. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value is a JSON object detailing the specifics about the support for the claim
}

export interface CredentialsSupported {
  [credentialId: string]: CredentialMetadataV1_09; //A JSON object containing a list of key value pairs, where the key is a string serving as an abstract identifier of the Credential. This identifier is RECOMMENDED to be collision resistant - it can be globally unique, but does not have to be when naming conflicts are unlikely to arise in a given use case. The value is a JSON object. The JSON object MUST conform to the structure of the Section 11.2.1.
}

export interface Logo {
  url?: string; //OPTIONAL. URL where the Wallet can obtain a logo of the Credential issuer.
  alt_text?: string; //OPTIONAL. String value of an alternative text of a logo image.
  //the following was a mistake in the v1_0-09 document (writers missed indentation, they've fixed that in 11)
  /*description?: string; //OPTIONAL. String value of a description of the Credential.
  background_color?: string; //OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
  text_color?: string; //OPTIONAL. String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure*/
}

export interface ClaimSupport {
  mandatory?: boolean; //OPTIONAL. Boolean which when set to true indicates the claim MUST be present in the issued Credential. If the mandatory property is omitted its default should be assumed to be false.
  namespace?: string; //OPTIONAL. String value of a namespace that the claim belongs to. Relevant for ISO/IEC 18013-5 (mobile Driving License) specification.
  value_type?: string; //OPTIONAL. String value determining type of value of the claim. A non-exhaustive list of valid values defined by this specification are string, number, and image media types such as image/jpeg as defined in IANA media type registry for images (https://www.iana.org/assignments/media-types/media-types.xhtml#image).
  display?: ClaimDisplay[];

  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure
}

export interface Claims {
  [claimId: string]: ClaimSupport;
}

export type OpenID4VCICredentialFormatTypes = CredentialFormat | 'mdl_iso' | 'ac_vc' | string;

export interface CredentialFormatSupport {
  types: string[]; //REQUIRED. Array of strings representing a format specific type of a Credential. This value corresponds to type in W3C [VC_DATA] and a doctype in ISO/IEC 18013-5 (mobile Driving License).
  cryptographic_binding_methods_supported?: ('jwk' | 'cose_key' | 'did' | string)[]; //OPTIONAL. Array of case sensitive strings that identify how the Credential is bound to the identifier of the End-User who possesses the Credential as defined in Section 9.1. A non-exhaustive list of valid values defined by this specification are did, jwk, and mso.
  cryptographic_suites_supported?: ('jwt_vc' | 'ldp_vc' | string)[]; //OPTIONAL. Array of case sensitive strings that identify the cryptographic suites that are supported for the cryptographic_binding_methods_supported. Cryptosuites for Credentials in jwt_vc format should use algorithm names defined in IANA JOSE Algorithms Registry. Cryptosuites for Credentials in ldp_vc format should use signature suites names defined in Linked Data Cryptographic Suite Registry.
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure
}

export type Formats = {
  [format in OpenID4VCICredentialFormatTypes]: CredentialFormatSupport;
};

export interface ClaimDisplay {
  name?: string; //OPTIONAL. String value of a display name for the claim.
  locale?: string; //OPTIONAL. String value that identifies language of this object represented as language tag values defined in BCP47 [RFC5646]. There MUST be only one object with the same language identifier.
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure
}

export interface IssuerDisplay {
  name?: string; //OPTIONAL. String value of a display name for the Credential issuer.
  locale?: string; //OPTIONAL. String value that identifies language of this object represented as language tag values defined in BCP47 [RFC5646]. There MUST be only one object with the same language identifier
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure
}
