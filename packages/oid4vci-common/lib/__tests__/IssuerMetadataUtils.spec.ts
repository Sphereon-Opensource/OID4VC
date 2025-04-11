import { describe, expect, it } from 'vitest';

import { getTypesFromCredentialSupported } from '../functions';
import { CredentialConfigurationSupportedV1_0_13 } from '../types';

describe('IssuerMetadataUtils should', () => {
  it('return the types from a credential supported with jwt_vc_json format', () => {
    const credentialSupported: CredentialConfigurationSupportedV1_0_13 = {
      format: 'jwt_vc_json',
      credential_definition: {
        type: ['VerifiableCredential', 'BevoegdheidUittreksel'],
      },
    };

    const result: string[] = getTypesFromCredentialSupported(credentialSupported);
    expect(result).toEqual(['VerifiableCredential', 'BevoegdheidUittreksel']);
  });

  it('filter out "VerifiableCredential" type if filterVerifiableCredential option is true', () => {
    const credentialSupported: CredentialConfigurationSupportedV1_0_13 = {
      format: 'jwt_vc_json',
      credential_definition: {
        type: ['VerifiableCredential', 'BevoegdheidUittreksel'],
      },
    };

    const result: string[] = getTypesFromCredentialSupported(credentialSupported, { filterVerifiableCredential: true });
    expect(result).toEqual(['BevoegdheidUittreksel']);
  });

  it('throw an error if types cannot be deduced', () => {
    const credentialSupported: CredentialConfigurationSupportedV1_0_13 = {
      format: 'unknown_format',
    } as unknown as CredentialConfigurationSupportedV1_0_13;

    expect(() => {
      getTypesFromCredentialSupported(credentialSupported);
    }).toThrow('Could not deduce types from credential supported');
  });
});
