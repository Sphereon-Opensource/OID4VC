import { W3CVerifiableCredential } from '@sphereon/ssi-types';

import { CredentialFormat } from './types';

export interface CredentialResponse {
  credential: W3CVerifiableCredential;
  format: CredentialFormat;
}

export interface CredentialResponseError {
  error: CredentialResponseErrorCode;
  error_description?: string;
  error_uri?: string;
}

export enum CredentialResponseErrorCode {
  INVALID_OR_MISSING_PROOF = 'invalid_or_missing_proof',
  INVALID_REQUEST = 'invalid_request',
  INVALID_TOKEN = 'invalid_token',
  UNSUPPORTED_TYPE = 'unsupported_type',
  UNSUPPORTED_FORMAT = 'unsupported_format',
  INVALID_CREDENTIAL = 'invalid_credential',
}
