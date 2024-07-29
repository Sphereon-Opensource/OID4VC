import { CredentialFormat } from '@sphereon/ssi-types';

import { ProofOfPossession } from './CredentialIssuance.types';
import { CredentialsSupportedDisplay, CredentialSupportedBrief, IssuerCredentialSubject, MetadataDisplay, NameAndLocale } from './Generic.types';

export interface CredentialRequestV1_0_08 {
  type: string;
  format: CredentialFormat;
  proof?: ProofOfPossession;
}

export interface IssuerMetadataV1_0_08 {
  issuer?: string;
  credential_endpoint: string; // REQUIRED. URL of the OP's Credential Endpoint. This URL MUST use the https scheme and MAY contain port, path and query parameter components.
  credentials_supported: CredentialSupportedTypeV1_0_08; // REQUIRED. A JSON object containing a list of key value pairs, where the key is a string serving as an abstract identifier of the Credential. This identifier is RECOMMENDED to be collision resistant - it can be globally unique, but does not have to be when naming conflicts are unlikely to arise in a given use case. The value is a JSON object. The JSON object MUST conform to the structure of the Section 11.2.1.
  credential_issuer?: {
    //  OPTIONAL. A JSON object containing display properties for the Credential issuer.
    display: NameAndLocale | NameAndLocale[]; // OPTIONAL. An array of objects, where each object contains display properties of a Credential issuer for a certain language. Below is a non-exhaustive list of valid parameters that MAY be included:
  };
  authorization_server?: string;
  token_endpoint?: string;
  display?: MetadataDisplay[];
  [x: string]: unknown;
}

export interface CredentialOfferPayloadV1_0_08 {
  issuer: string; //(url) REQUIRED The issuer URL of the Credential issuer, the Wallet is requested to obtain one or more Credentials from.
  credential_type: string[] | string; //(url) REQUIRED A JSON string denoting the type of the Credential the Wallet shall request
  'pre-authorized_code'?: string; //CONDITIONAL the code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short-lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean | string; //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
  op_state?: string; //(JWT) OPTIONAL String value created by the Credential Issuer and opaque to the Wallet that is used to bind the subsequent authentication request with the Credential Issuer to a context set up during previous steps
}
export interface CredentialSupportedTypeV1_0_08 {
  [credentialType: string]: CredentialSupportedV1_0_08;
}

export interface CredentialSupportedFormatV1_0_08 extends CredentialSupportedBrief {
  name?: string;
  types: string[];
}

export interface CredentialSupportedV1_0_08 {
  display?: CredentialsSupportedDisplay[];
  formats: {
    // REQUIRED. A JSON object containing a list of key value pairs, where the key is a string identifying the format of the Credential. Below is a non-exhaustive list of valid key values defined by this specification:
    [credentialFormat: string]: CredentialSupportedFormatV1_0_08;
  };
  claims?: IssuerCredentialSubject; // REQUIRED. A JSON object containing a list of key value pairs, where the key identifies the claim offered in the Credential. The value is a JSON object detailing the specifics about the support for the claim with a following non-exhaustive list of parameters that MAY be included:
}
