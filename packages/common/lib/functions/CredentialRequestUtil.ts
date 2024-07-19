import {
  CredentialRequest,
  CredentialRequestV1_0_08,
  CredentialRequestV1_0_11,
  CredentialRequestV1_0_13,
  OpenId4VCIVersion,
  UniformCredentialRequest,
} from '../types';

import { getFormatForVersion } from './FormatUtils';

export function getTypesFromRequest(credentialRequest: CredentialRequest, opts?: { filterVerifiableCredential: boolean }) {
  let types: string[] = [];
  console.log(credentialRequest);
  if ('credential_identifier' in credentialRequest && credentialRequest.credential_identifier) {
    throw Error(`Cannot get types from request when it contains a credential_identifier`);
  } else if (
    credentialRequest.format === 'jwt_vc_json-ld' ||
    credentialRequest.format === 'ldp_vc' ||
    credentialRequest.format === 'jwt_vc' ||
    credentialRequest.format === 'jwt_vc_json'
  ) {
    if ('credential_definition' in credentialRequest && credentialRequest.credential_definition) {
      types =
        'types' in credentialRequest.credential_definition
          ? credentialRequest.credential_definition.types
          : credentialRequest.credential_definition.type;
    }

    if ('type' in credentialRequest && Array.isArray(credentialRequest.type)) {
      types = credentialRequest.type;
    }

    if ('types' in credentialRequest && Array.isArray(credentialRequest.types)) {
      types = credentialRequest.types;
    }
  } else if (credentialRequest.format === 'vc+sd-jwt' && 'vct' in credentialRequest) {
    types = [credentialRequest.vct];
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
): UniformCredentialRequest | CredentialRequestV1_0_08 | CredentialRequestV1_0_11 | CredentialRequestV1_0_13 {
  if (version === OpenId4VCIVersion.VER_1_0_08) {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const draft8Format = getFormatForVersion(credentialRequest.format!, version);
    const types = getTypesFromRequest(credentialRequest, { filterVerifiableCredential: true });

    if (credentialRequest.credential_subject_issuance) {
      throw Error('Experimental subject issuance is not supported for older versions of the spec');
    }
    return {
      format: draft8Format,
      proof: credentialRequest.proof,
      type: types[0],
    } satisfies CredentialRequestV1_0_08;
    /* } else if (version === OpenId4VCIVersion.VER_1_0_11) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    const { credential_definition = undefined, ...requestv11 } = credentialRequest;
    return {
      ...requestv11,
      ...credential_definition,
    } as CredentialRequestV1_0_11;*/
  }

  return credentialRequest;
}
