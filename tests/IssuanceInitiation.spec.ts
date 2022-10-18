import { IssuanceInitiation } from '../lib';

const INITIATION_TEST_URI =
  'https://server.example.com?issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy';

describe('Authorization Request', () => {
  it('Should return Issuance Initiation Request with base URL from URI', () => {
    expect(IssuanceInitiation.fromURI(INITIATION_TEST_URI)).toEqual({
      baseUrl: 'https://server.example.com',
      issuanceInitiationRequest: {
        credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        issuer: 'https://server.example.com',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
      },
    });
  });

  it('Should return URI from Issuance Initiation Request', () => {
    const initiationWithUrl = IssuanceInitiation.fromURI(INITIATION_TEST_URI);
    expect(IssuanceInitiation.toURI(initiationWithUrl)).toEqual(INITIATION_TEST_URI);
  });
});
