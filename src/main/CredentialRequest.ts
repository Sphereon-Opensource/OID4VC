import { CredentialFormat, CredentialType, ProofOfPossesion } from './types';

export interface CredentialRequest {
  //TODO: handling list is out of scope for now
  type: CredentialType | CredentialType[];
  //TODO: handling list is out of scope for now
  format: CredentialFormat | CredentialFormat[];
  proof: ProofOfPossesion;
}
