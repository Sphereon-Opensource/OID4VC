import {
  CredentialRequest,
  CredentialRequestV1_0_08,
  CredentialRequestV1_0_11,
  CredentialRequestV1_0_13, CredentialRequestV1_0_15,
  OID4VCICredentialFormat,
  OpenId4VCIVersion,
  UniformCredentialRequest
} from '../types'

export function getTypesFromRequest(credentialRequest: CredentialRequest, format: OID4VCICredentialFormat, opts?: { filterVerifiableCredential: boolean }) {
  let types: string[] = []
  if ('credential_identifier' in credentialRequest && credentialRequest.credential_identifier) {
    throw Error(`Cannot get types from request when it contains a credential_identifier`)
  } else if (
    format === 'jwt_vc_json-ld' ||
    format === 'ldp_vc' ||
    format === 'jwt_vc' ||
    format === 'jwt_vc_json'
  ) {
    if ('credential_definition' in credentialRequest && credentialRequest.credential_definition) {
      types =
        'types' in credentialRequest.credential_definition
          ? credentialRequest.credential_definition.types
          : credentialRequest.credential_definition.type
    }

    if ('type' in credentialRequest && Array.isArray(credentialRequest.type)) {
      types = credentialRequest.type
    }

    if ('types' in credentialRequest && Array.isArray(credentialRequest.types)) {
      types = credentialRequest.types
    }
  } else if (format === 'dc+sd-jwt' && 'vct' in credentialRequest) {
    types = [credentialRequest.vct]
  } else if (format === 'mso_mdoc' && 'doctype' in credentialRequest) {
    types = [credentialRequest.doctype]
  }

  if (!types || types.length === 0) {
    throw Error('Could not deduce types from credential request')
  }
  if (opts?.filterVerifiableCredential) {
    return types.filter((type) => type !== 'VerifiableCredential')
  }
  return types
}

export function getCredentialRequestForVersion(
  credentialRequest: UniformCredentialRequest,
  format: OID4VCICredentialFormat,
  version: OpenId4VCIVersion,
): UniformCredentialRequest | CredentialRequestV1_0_08 | CredentialRequestV1_0_11 | CredentialRequestV1_0_13 | CredentialRequestV1_0_15 {
  if (version === OpenId4VCIVersion.VER_1_0_08) {
    const types = getTypesFromRequest(credentialRequest, format, { filterVerifiableCredential: true })

    if (credentialRequest.credential_subject_issuance) {
      throw Error('Experimental subject issuance is not supported for older versions of the spec')
    }
    return {
      format,
      proof: credentialRequest.proof,
      type: types[0],
    } satisfies CredentialRequestV1_0_08
    /* } else if (version === OpenId4VCIVersion.VER_1_0_11) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    const { credential_definition = undefined, ...requestv11 } = credentialRequest;
    return {
      ...requestv11,
      ...credential_definition,
    } as CredentialRequestV1_0_11;*/
  }

  return credentialRequest
}
