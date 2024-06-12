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
  if ('credential_identifier' in credentialRequest && credentialRequest.credential_identifier) {
    throw Error(`Cannot get types from request when it contains a credential_identifier`);
  } else if (credentialRequest.format === 'jwt_vc_json' || credentialRequest.format === 'jwt_vc') {
    types = 'types' in credentialRequest ? credentialRequest.types : [];
  } else if (credentialRequest.format === 'jwt_vc_json-ld' || credentialRequest.format === 'ldp_vc') {
    types =
      'credential_definition' in credentialRequest && credentialRequest.credential_definition
        ? credentialRequest.credential_definition.types
        : // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          'types' in credentialRequest.types
          ? (credentialRequest['types' as keyof CredentialRequest] as unknown as string[])
          : [];
  } else if (credentialRequest.format === 'vc+sd-jwt') {
    types = 'vct' in credentialRequest ? [credentialRequest.vct as string] : [];
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
