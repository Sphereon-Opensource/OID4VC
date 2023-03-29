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
      version: 9,
    });
  });

  it('Should return Issuance Initiation Request with base URL from openid-initiate-issuance URI', () => {
    expect(CredentialOffer.fromURI(INITIATION_TEST_URI)).toEqual(INITIATION_TEST);
  });

  it('Should return Issuance Initiation URI from request', () => {
    const uri = CredentialOffer.toURI(INITIATION_TEST);
    expect(uri).toEqual(INITIATION_TEST_URI);
  });

  it('Should return URI from Issuance Initiation Request', () => {
    const initiationWithUrl = CredentialOffer.fromURI(INITIATION_TEST_HTTPS_URI);
    expect(CredentialOffer.toURI(initiationWithUrl)).toEqual(INITIATION_TEST_HTTPS_URI);
  });

  it('Should throw error on invalid URI', () => {
    expect(() => CredentialOffer.fromURI(INITIATION_TEST_HTTPS_URI.replace('?', ''))).toThrowError('Invalid Issuance Initiation Request Payload');
  });
});
