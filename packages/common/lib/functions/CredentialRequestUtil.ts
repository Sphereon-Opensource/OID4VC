import { OpenId4VCIVersion, UniformCredentialRequest } from '../types';

export function getTypesFromRequest(credentialRequest: UniformCredentialRequest, opts?: { filterVerifiableCredential: boolean }) {
  let types: string[] = [];
  if (credentialRequest.format === 'jwt_vc_json') {
    types = credentialRequest.types;
  } else if (credentialRequest.format === 'jwt_vc_json-ld' || credentialRequest.format === 'ldp_vc') {
    types = credentialRequest.credential_definition.types;
  } else if (credentialRequest.format === 'vc+sd-jwt') {
    types = [credentialRequest.credential_definition.vct];
  }

  if (!types || types.length === 0) {
    throw Error('Could not deduce types from credential request');
  }
  if (opts?.filterVerifiableCredential) {
    return types.filter((type) => type !== 'VerifiableCredential');
  }
  return types;
}

export function getCredentialRequestForVersion(
  credentialRequest: UniformCredentialRequest,
  version: OpenId4VCIVersion,
): UniformCredentialRequest {
  return credentialRequest;
}
