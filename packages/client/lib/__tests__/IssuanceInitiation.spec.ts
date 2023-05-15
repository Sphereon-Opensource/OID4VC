import { OpenId4VCIVersion } from '@sphereon/oid4vci-common';

import { CredentialOffer } from '../CredentialOffer';

import { INITIATION_TEST, INITIATION_TEST_HTTPS_URI, INITIATION_TEST_URI } from './MetadataMocks';

describe('Issuance Initiation', () => {
  it('Should return Issuance Initiation Request with base URL from https URI', async () => {
    expect(await CredentialOffer.fromURI(INITIATION_TEST_HTTPS_URI)).toEqual({
      baseUrl: 'https://server.example.com',
      request: {
        credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        issuer: 'https://server.example.com',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
      },
      version: OpenId4VCIVersion.VER_1_0_09,
    });
  });

  it('Should return Issuance Initiation Request with base URL from openid-initiate-issuance URI', async () => {
    expect(await CredentialOffer.fromURI(INITIATION_TEST_URI)).toEqual(INITIATION_TEST);
  });

  it('Should return Issuance Initiation URI from request', async () => {
    expect(await CredentialOffer.toURI(INITIATION_TEST)).toEqual(INITIATION_TEST_URI);
  });

  it('Should return URI from Issuance Initiation Request', async () => {
    const issuanceInitiationClient = await CredentialOffer.fromURI(INITIATION_TEST_HTTPS_URI);
    expect(await CredentialOffer.toURI(issuanceInitiationClient)).toEqual(INITIATION_TEST_HTTPS_URI);
  });

  it('Should throw error on invalid URI', async () => {
    const issuanceInitiationURI = INITIATION_TEST_HTTPS_URI.replace('?', '');
    await expect(async () => CredentialOffer.fromURI(issuanceInitiationURI)).rejects.toThrowError('Invalid Credential Offer Request');
  });
});
