import { CredentialRequestV1_0_11 } from '../types';

export function getTypesFromRequest(credentialRequest: CredentialRequestV1_0_11, opts?: { filterVerifiableCredential: boolean }) {
  const types = 'types' in credentialRequest ? credentialRequest.types : credentialRequest.credential_definition.types;
  if (!types || types.length === 0) {
    throw Error('Could not deduce types from credential request');
  }
  if (opts?.filterVerifiableCredential) {
    return types.filter((type) => type !== 'VerifiableCredential');
  }
  return types;
}
