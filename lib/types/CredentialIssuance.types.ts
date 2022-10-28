import { CredentialFormat, W3CVerifiableCredential } from '@sphereon/ssi-types';

export interface CredentialRequest {
  //TODO: handling list is out of scope for now
  type: string | string[];
  //TODO: handling list is out of scope for now
  format: CredentialFormat | CredentialFormat[];
  proof: ProofOfPossession;
}

export interface CredentialResponse {
  credential: W3CVerifiableCredential;
  format: CredentialFormat;
}

export interface IssuanceInitiationWithBaseUrl {
  baseUrl: string;
  issuanceInitiationRequest: IssuanceInitiationRequestPayload;
}

export interface IssuanceInitiationRequestPayload {
  issuer: string; //(url) REQUIRED The issuer URL of the Credential issuer, the Wallet is requested to obtain one or more Credentials from.
  credential_type: string[] | string; //(url) REQUIRED A JSON string denoting the type of the Credential the Wallet shall request
  'pre-authorized_code'?: string; //CONDITIONAL the code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short-lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean | string; //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
  op_state?: string; //(JWT) OPTIONAL String value created by the Credential Issuer and opaque to the Wallet that is used to bind the subsequent authentication request with the Credential Issuer to a context set up during previous steps
}

export enum ProofType {
  JWT = 'jwt',
}

export interface ProofOfPossession {
  proof_type: ProofType;
  jwt: string;

  [x: string]: unknown;
}

export type SearchValue = {
  // eslint-disable-next-line  @typescript-eslint/no-explicit-any
  [Symbol.replace](string: string, replacer: (substring: string, ...args: any[]) => string): string;
};

export type EncodeJsonAsURIOpts = { uriTypeProperties?: string[]; arrayTypeProperties?: string[]; baseUrl?: string };

export type DecodeURIAsJsonOpts = { requiredProperties?: string[]; arrayTypeProperties?: string[] };

export interface ProofOfPossessionCallbackArgs {
  kid: string; // can be the did of the wallet
  [x: string]: unknown;
}

export interface ProofOfPossessionOpts {
  proofOfPossessionCallback: ProofOfPossessionCallback;
  proofOfPossessionCallbackArgs: ProofOfPossessionCallbackArgs;
}

export type ProofOfPossessionCallback = (args: ProofOfPossessionCallbackArgs) => Promise<ProofOfPossession>;

export type Request = CredentialRequest;
