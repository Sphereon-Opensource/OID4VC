export interface IssuanceInitiationRequestPayload {
  issuer: string; //(url) REQUIRED The issuer URL of the Credential issuer, the Wallet is requested to obtain one or more Credentials from.
  credential_type: string[]; //(url) REQUIRED A JSON string denoting the type of the Credential the Wallet shall request
  pre_authorized_code?: string; //CONDITIONAL he code representing the issuer's authorization for the Wallet to obtain Credentials of a certain type. This code MUST be short lived and single-use. MUST be present in a pre-authorized code flow.
  user_pin_required?: boolean; //OPTIONAL Boolean value specifying whether the issuer expects presentation of a user PIN along with the Token Request in a pre-authorized code flow. Default is false.
  op_state?: string; //(JWT) OPTIONAL String value created by the Credential Issuer and opaque to the Wallet that is used to bind the sub-sequent authentication request with the Credential Issuer to a context set up during previous steps
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type SearchValue = { [Symbol.replace](string: string, replacer: (substring: string, ...args: any[]) => string): string };
