import { W3CVerifiableCredential } from '@sphereon/ssi-types';
import { ClaimFormat } from '@sphereon/ssi-types/src/types/vc';

export interface CredentialRequest {
  //TODO: handling list is out of scope for now
  type: string | string[];
  //TODO: handling list is out of scope for now
  format: ClaimFormat | ClaimFormat[];
  proof: ProofOfPossession;
}

export enum ProofType {
  JWT = 'jwt',
}

export interface CredentialResponse {
  credential: W3CVerifiableCredential;
  format: ClaimFormat;
}

export interface CredentialResponseError {
  error: CredentialResponseErrorCode;
  error_description?: string;
  error_uri?: string;
}

export enum CredentialResponseErrorCode {
  UNKNOWN = 'unknown exception occurred',
  INVALID_OR_MISSING_PROOF = 'invalid_or_missing_proof',
  INVALID_REQUEST = 'invalid_request',
  INVALID_TOKEN = 'invalid_token',
  UNSUPPORTED_TYPE = 'unsupported_type',
  UNSUPPORTED_FORMAT = 'unsupported_format',
  INVALID_CREDENTIAL = 'invalid_credential',
}

export interface ProofOfPossession {
  proof_type: ProofType;
  jwt: string;
  [x: string]: any;
}

export type Request = CredentialRequest;
