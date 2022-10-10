import { W3CVerifiableCredential } from '@sphereon/ssi-types';

import { CredentialFormat } from './types';

export interface CredentialResponse {
  credential: W3CVerifiableCredential;
  format: CredentialFormat;
}
