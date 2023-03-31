import { OpenId4VCIVersion } from '@sphereon/openid4vci-common';

import { CredentialOffer } from '../CredentialOffer';

import { INITIATION_TEST, INITIATION_TEST_HTTPS_URI, INITIATION_TEST_URI } from './MetadataMocks';

describe('Issuance Initiation', () => {
  it('Should return Issuance Initiation Request with base URL from https URI', () => {
    expect(CredentialOffer.fromURI(INITIATION_TEST_HTTPS_URI)).toEqual({
      baseUrl: 'https://server.example.com',
      request: {
        credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        issuer: 'https://server.example.com',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
      },
      version: OpenId4VCIVersion.VER_9,
    });
  });

  it('Should return Issuance Initiation Request with base URL from openid-initiate-issuance URI', () => {
    expect(CredentialOffer.fromURI(INITIATION_TEST_URI)).toEqual(INITIATION_TEST);
  });

  it('Should return Issuance Initiation URI from request', () => {
    expect(CredentialOffer.toURI(INITIATION_TEST)).toEqual(INITIATION_TEST_URI);
  });

  it('Should return URI from Issuance Initiation Request', () => {
    const issuanceInitiationClient = CredentialOffer.fromURI(INITIATION_TEST_HTTPS_URI);
    expect(CredentialOffer.toURI(issuanceInitiationClient)).toEqual(INITIATION_TEST_HTTPS_URI);
  });

  it('Should throw error on invalid URI', () => {
    const issuanceInitiationURI = INITIATION_TEST_HTTPS_URI.replace('?', '');
    expect(() => CredentialOffer.fromURI(issuanceInitiationURI)).toThrowError('Invalid Issuance Initiation Request Payload');
  });
});
