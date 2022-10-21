import { IssuanceInitiation } from '../lib';

const INITIATION_TEST_HTTPS_URI =
  'https://server.example.com?issuer=https%3A%2F%2Fserver%2Eexample%2Ecom&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FhealthCard&credential_type=https%3A%2F%2Fdid%2Eexample%2Eorg%2FdriverLicense&op_state=eyJhbGciOiJSU0Et...FYUaBy';
const INITIATION_TEST_URI =
  'openid-initiate-issuance://?issuer=https%3A%2F%2Fjff.walt.id%2Fissuer-api%2Foidc%2F&credential_type=OpenBadgeCredential&pre-authorized_code=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE&user_pin_required=false';

describe('Authorization Request', () => {
  it('Should return Issuance Initiation Request with base URL from https URI', () => {
    expect(IssuanceInitiation.fromURI(INITIATION_TEST_HTTPS_URI)).toEqual({
      baseUrl: 'https://server.example.com',
      issuanceInitiationRequest: {
        credential_type: ['https://did.example.org/healthCard', 'https://did.example.org/driverLicense'],
        issuer: 'https://server.example.com',
        op_state: 'eyJhbGciOiJSU0Et...FYUaBy',
      },
    });
  });

  it('Should return Issuance Initiation Request with base URL from openid-initiate-issuance URI', () => {
    expect(IssuanceInitiation.fromURI(INITIATION_TEST_URI)).toEqual({
      baseUrl: 'openid-initiate-issuance://',
      issuanceInitiationRequest: {
        credential_type: 'OpenBadgeCredential',
        issuer: 'https://jff.walt.id/issuer-api/oidc/',
        'pre-authorized_code':
          'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhOTUyZjUxNi1jYWVmLTQ4YjMtODIxYy00OTRkYzgyNjljZjAiLCJwcmUtYXV0aG9yaXplZCI6dHJ1ZX0.YE5DlalcLC2ChGEg47CQDaN1gTxbaQqSclIVqsSAUHE',
        user_pin_required: 'false',
      },
    });
  });

  it('Should return URI from Issuance Initiation Request', () => {
    const initiationWithUrl = IssuanceInitiation.fromURI(INITIATION_TEST_HTTPS_URI);
    expect(IssuanceInitiation.toURI(initiationWithUrl)).toEqual(INITIATION_TEST_HTTPS_URI);
  });

  it('Should throw error on invalid URI', () => {
    expect(() => IssuanceInitiation.fromURI(INITIATION_TEST_HTTPS_URI.replace('?', ''))).toThrowError('Invalid Issuance Initiation Request Payload');
  });
});
