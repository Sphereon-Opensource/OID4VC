import { IssuanceInitiationClient } from '../CredentialOffer';

import { INITIATION_TEST, INITIATION_TEST_HTTPS_URI, INITIATION_TEST_URI } from './MetadataMocks';

describe('Issuance Initiation', () => {
  it('Should return Issuance Initiation Request with base URL from https URI', () => {

    expect(new IssuanceInitiationClient(INITIATION_TEST_HTTPS_URI).issuanceInitiationWithBaseUrl).toEqual({
      baseUrl: 'https://server.example.com',
      issuanceInitiationRequest: {
        credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        issuer: 'https://server.example.com',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
      },
    });
  });

  it('Should return Issuance Initiation Request with base URL from openid-initiate-issuance URI', () => {
    expect(new IssuanceInitiationClient(INITIATION_TEST_URI).issuanceInitiationWithBaseUrl).toEqual(INITIATION_TEST);
  });

  it('Should return Issuance Initiation URI from request', () => {
    const uri = new IssuanceInitiationClient(INITIATION_TEST_URI).toURI();
    expect(uri).toEqual(INITIATION_TEST_URI);
  });

  it('Should return URI from Issuance Initiation Request', () => {
    const issuanceInitiation = new IssuanceInitiationClient(INITIATION_TEST_HTTPS_URI);
    expect(issuanceInitiation.toURI()).toEqual(INITIATION_TEST_HTTPS_URI);
  });

  it('Should throw error on invalid URI', () => {
    const issuanceInitiationURI = INITIATION_TEST_HTTPS_URI.replace('?', '');
    expect(() => new IssuanceInitiationClient(issuanceInitiationURI).issuanceInitiationWithBaseUrl).toThrowError('Invalid Issuance Initiation Request Payload');
  });
});
