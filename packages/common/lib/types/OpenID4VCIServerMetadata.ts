import { CredentialFormat } from '@sphereon/ssi-types';

import { Display, IssuerCredentialSubject, NameAndLocaleExtended } from './Generic.types';
import { OAuth2ASMetadata } from './OAuth2ASMetadata';

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.2
export interface OpenID4VCIServerMetadata {
  credential_endpoint: string; //REQUIRED. URL of the OP's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  credentials_supported: IssuerCredentialSubject; //REQUIRED. A JSON object containing a list of key value pairs, where the key is a string serving as an abstract identifier of the Credential. This identifier is RECOMMENDED to be collision resistant - it can be globally unique, but does not have to be when naming conflicts are unlikely to arise in a given use case. The value is a JSON object. The JSON object MUST conform to the structure of the Section 11.2.1.
  credential_issuer?: CredentialIssuer; //  A JSON object containing display properties for the Credential issuer.
  token_endpoint?: string; //NON-SPEC compliant, but used by several issuers. URL of the OP's Token Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  authorization_server?: string; //NON-SPEC compliant, but used by some issuers. URL of the AS. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  // TODO: The above authorization_server being used in the wild, serves roughly the same purpose as the below spec compliant endpoint. Look at how to use authorization_server as authorization_endpoint in case it is present
  authorization_endpoint?: string;
  pushed_authorization_request_endpoint?: string; // The URL of the pushed authorization request endpoint at which a client can post an authorization request to exchange for a request_uri value usable at the authorization server
  // Note that the presence of pushed_authorization_request_endpoint is sufficient for a client to determine that it may use the PAR flow. A request_uri value obtained from the PAR endpoint is usable at the authorization endpoint regardless of other authorization server metadata such as request_uri_parameter_supported or require_request_uri_registration
  require_pushed_authorization_endpoint?: boolean; // Boolean parameter indicating whether the authorization server accepts authorization request data only via PAR. If omitted, the default value is false.
}

export type Oauth2ASWithOID4VCIMetadata = OAuth2ASMetadata & OpenID4VCIServerMetadata;

export interface CredentialIssuer {
  display?: NameAndLocaleExtended; //OPTIONAL. An array of objects, where each object contains display properties of a Credential issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-metadata-object
export interface CredentialMetadata {
  display?: Display[]; //OPTIONAL. An array of objects, where each object contains display properties of a certain Credential for a certain language. Below is a non-exhaustive list of parameters that MAY be included. Note that the display name of the Credential is obtained from display.name and individual claim names from claims.display.name values.
  formats: Formats; //REQUIRED. A JSON object containing a list of key value pairs, where the key is a string identifying the format of the Credential. Below is a non-exhaustive list of valid key values defined by this specification:
  claims?: IssuerCredentialSubject; //REQUIRED. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value is a JSON object detailing the specifics about the support for the claim
}

export type OpenID4VCICredentialFormatTypes = CredentialFormat | 'mdl_iso' | 'ac_vc' | string;

export interface CredentialFormatSupport {
  types: string[]; //REQUIRED. Array of strings representing a format specific type of a Credential. This value corresponds to type in W3C [VC_DATA] and a doctype in ISO/IEC 18013-5 (mobile Driving License).
  cryptographic_binding_methods_supported?: string[]; //OPTIONAL. Array of case sensitive strings that identify how the Credential is bound to the identifier of the End-User who possesses the Credential as defined in Section 9.1. A non-exhaustive list of valid values defined by this specification are did, jwk, and mso.
  cryptographic_suites_supported?: string[]; //OPTIONAL. Array of case sensitive strings that identify the cryptographic suites that are supported for the cryptographic_binding_methods_supported. Cryptosuites for Credentials in jwt_vc format should use algorithm names defined in IANA JOSE Algorithms Registry. Cryptosuites for Credentials in ldp_vc format should use signature suites names defined in Linked Data Cryptographic Suite Registry.
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [x: string]: any; //We use any, so you can access properties if you know the structure
}

export type Formats = {
  [format in OpenID4VCICredentialFormatTypes]: CredentialFormatSupport;
};
