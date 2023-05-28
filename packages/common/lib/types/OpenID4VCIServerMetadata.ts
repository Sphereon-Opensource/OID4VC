import { CredentialIssuerMetadata } from './Generic.types';
import { OAuth2ASMetadata } from './OAuth2ASMetadata';

export type Oauth2ASWithOID4VCIMetadata = OAuth2ASMetadata & CredentialIssuerMetadata;

// export type OpenID4VCICredentialFormatTypes = CredentialFormat | 'mdl_iso' | 'ac_vc' | string;

/*export interface CredentialFormatSupport {
  types: string[]; //REQUIRED. Array of strings representing a format specific type of a Credential. This value corresponds to type in W3C [VC_DATA] and a doctype in ISO/IEC 18013-5 (mobile Driving License).
  cryptographic_binding_methods_supported?: string[]; //OPTIONAL. Array of case sensitive strings that identify how the Credential is bound to the identifier of the End-User who possesses the Credential as defined in Section 9.1. A non-exhaustive list of valid values defined by this specification are did, jwk, and mso.
  cryptographic_suites_supported?: string[]; //OPTIONAL. Array of case sensitive strings that identify the cryptographic suites that are supported for the cryptographic_binding_methods_supported. Cryptosuites for Credentials in jwt_vc format should use algorithm names defined in IANA JOSE Algorithms Registry. Cryptosuites for Credentials in ldp_vc format should use signature suites names defined in Linked Data Cryptographic Suite Registry.
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure
}*/
/*

export type Formats = {
  [format in OpenID4VCICredentialFormatTypes]: CredentialFormatSupport;
};
*/
