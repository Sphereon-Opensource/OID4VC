import { determineSpecVersionFromURI, getClientIdFromCredentialOfferPayload } from '../functions';
import { CredentialOfferPayload, OpenId4VCIVersion } from '../types';

export const UNIT_TEST_TIMEOUT = 30000;

describe('CredentialOfferUtil should', () => {
  const INITIATE_QR_V8 =
    'openid-initiate-issuance://?' +
    'issuer=https%3A%2F%2Fissuer.research.identiproof.io&' +
    'credential_type=OpenBadgeCredentialUrl&' +
    'pre-authorized_code=4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp&' +
    'user_pin_required=true';

  const INITIATE_QR_DATA_MIXED_V9 =
    'openid-initiate-issuance://?' +
    'credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D';

  const CREDENTIAL_OFFER_QR_V11 =
    'openid-credential-offer://?' +
    'credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D';

  it(
    'get version 8 with sample URL',
    async () => {
      expect(determineSpecVersionFromURI(INITIATE_QR_V8)).toEqual(OpenId4VCIVersion.VER_1_0_08);
    },
    UNIT_TEST_TIMEOUT,
  );

  it(
    'get version 11 with sample URL',
    async () => {
      expect(determineSpecVersionFromURI(CREDENTIAL_OFFER_QR_V11)).toEqual(OpenId4VCIVersion.VER_1_0_11);
    },
    UNIT_TEST_TIMEOUT,
  );

  it(
    'get exception for mixed attributes in URL',
    async () => {
      expect(() => determineSpecVersionFromURI(INITIATE_QR_DATA_MIXED_V9)).toThrow(
        Error("Invalid param. Some keys have been used from version: 1008 version while 'credential_issuer' is used from version: 1011"),
      );
    },
    UNIT_TEST_TIMEOUT,
  );

  it(
    'get version 11 as default value',
    async () => {
      expect(determineSpecVersionFromURI('test://uri')).toEqual(OpenId4VCIVersion.VER_1_0_11);
    },
    UNIT_TEST_TIMEOUT,
  );

  it('get client_id from JWT pre-auth code offer', () => {
    const offer = {
      credential_issuer: 'https://conformance-test.ebsi.eu/conformance/v3/issuer-mock',
      credentials: [
        {
          format: 'jwt_vc',
          types: ['VerifiableCredential', 'VerifiableAttestation', 'CTWalletCrossPreAuthorisedInTime'],
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          trust_framework: { name: 'ebsi', type: 'Accreditation', uri: 'TIR link towards accreditation' },
        },
      ],
      grants: {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          'pre-authorized_code':
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkJFTmRqRGZhdGxLai11UW92WUpsT184U2pPY1ZIdmk2SHJYS0xLRUI3UG8ifQ.eyJjbGllbnRfaWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnFTWlpGakc0dFZnS2hFd0twcm9qcUxCM0MyWXBqNEg3M1N0Z2pNa1NYZzJtUXh1V0xmenVSMTJRc052Z1FXenJ6S1NmN1lSQk5yUlhLNzF2ZnExMkJieXhUTEZFWkJXZm5IcWV6QlZHUWlOTGZxZXV5d1pIZ3N0TUNjUzQ0VFhmYjIiLCJhdXRob3JpemF0aW9uX2RldGFpbHMiOlt7InR5cGUiOiJvcGVuaWRfY3JlZGVudGlhbCIsImZvcm1hdCI6Imp3dF92YyIsImxvY2F0aW9ucyI6WyJodHRwczovL2NvbmZvcm1hbmNlLXRlc3QuZWJzaS5ldS9jb25mb3JtYW5jZS92My9pc3N1ZXItbW9jayJdLCJ0eXBlcyI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlZlcmlmaWFibGVBdHRlc3RhdGlvbiIsIkNUV2FsbGV0Q3Jvc3NQcmVBdXRob3Jpc2VkSW5UaW1lIl19XSwiaWF0IjoxNzA2MTI2NDI5LCJleHAiOjE3MDYxMjY3MjksImlzcyI6Imh0dHBzOi8vY29uZm9ybWFuY2UtdGVzdC5lYnNpLmV1L2NvbmZvcm1hbmNlL3YzL2lzc3Vlci1tb2NrIiwiYXVkIjoiaHR0cHM6Ly9jb25mb3JtYW5jZS10ZXN0LmVic2kuZXUvY29uZm9ybWFuY2UvdjMvYXV0aC1tb2NrIiwic3ViIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxU1paRmpHNHRWZ0toRXdLcHJvanFMQjNDMllwajRINzNTdGdqTWtTWGcybVF4dVdMZnp1UjEyUXNOdmdRV3pyektTZjdZUkJOclJYSzcxdmZxMTJCYnl4VExGRVpCV2ZuSHFlekJWR1FpTkxmcWV1eXdaSGdzdE1DY1M0NFRYZmIyIn0.Zq2o33CU4wlRNtWOIITI5qbJcuNc2c9hLwIio7OlsHBa5ZAyQR8UUU_r5EufSChe4ji15Ihrr20m5-oUiZW80A',
          user_pin_required: true,
        },
      },
    } as CredentialOfferPayload;
    expect(getClientIdFromCredentialOfferPayload(offer)).toEqual(
      'did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbqSZZFjG4tVgKhEwKprojqLB3C2Ypj4H73StgjMkSXg2mQxuWLfzuR12QsNvgQWzrzKSf7YRBNrRXK71vfq12BbyxTLFEZBWfnHqezBVGQiNLfqeuywZHgstMCcS44TXfb2',
    );
  });

  it('get client_id from JWT authorization code offer', () => {
    const offer = {
      credential_issuer: 'https://conformance-test.ebsi.eu/conformance/v3/issuer-mock',
      credentials: [
        {
          format: 'jwt_vc',
          types: ['VerifiableCredential', 'VerifiableAttestation', 'CTWalletCrossAuthorisedInTime'],
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          trust_framework: { name: 'ebsi', type: 'Accreditation', uri: 'TIR link towards accreditation' },
        },
      ],
      grants: {
        authorization_code: {
          issuer_state:
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6IkJFTmRqRGZhdGxLai11UW92WUpsT184U2pPY1ZIdmk2SHJYS0xLRUI3UG8ifQ.eyJjbGllbnRfaWQiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYnFTWlpGakc0dFZnS2hFd0twcm9qcUxCM0MyWXBqNEg3M1N0Z2pNa1NYZzJtUXh1V0xmenVSMTJRc052Z1FXenJ6S1NmN1lSQk5yUlhLNzF2ZnExMkJieXhUTEZFWkJXZm5IcWV6QlZHUWlOTGZxZXV5d1pIZ3N0TUNjUzQ0VFhmYjIiLCJjcmVkZW50aWFsX3R5cGVzIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiVmVyaWZpYWJsZUF0dGVzdGF0aW9uIiwiQ1RXYWxsZXRDcm9zc0F1dGhvcmlzZWRJblRpbWUiXSwiaWF0IjoxNzA2MTI1ODUwLCJleHAiOjE3MDYxMjYxNTAsImlzcyI6Imh0dHBzOi8vY29uZm9ybWFuY2UtdGVzdC5lYnNpLmV1L2NvbmZvcm1hbmNlL3YzL2lzc3Vlci1tb2NrIiwiYXVkIjoiaHR0cHM6Ly9jb25mb3JtYW5jZS10ZXN0LmVic2kuZXUvY29uZm9ybWFuY2UvdjMvYXV0aC1tb2NrIiwic3ViIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2JxU1paRmpHNHRWZ0toRXdLcHJvanFMQjNDMllwajRINzNTdGdqTWtTWGcybVF4dVdMZnp1UjEyUXNOdmdRV3pyektTZjdZUkJOclJYSzcxdmZxMTJCYnl4VExGRVpCV2ZuSHFlekJWR1FpTkxmcWV1eXdaSGdzdE1DY1M0NFRYZmIyIn0.jxzbE6OdqnJfLzSfwYcgRZQURI5UcAtuYU9gPOZYyUwjWMDtVo1k4PCYH4mnjok7pfj47ik8FnaHWE7d99u-_w',
        },
      },
    } as CredentialOfferPayload;
    expect(getClientIdFromCredentialOfferPayload(offer)).toEqual(
      'did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbqSZZFjG4tVgKhEwKprojqLB3C2Ypj4H73StgjMkSXg2mQxuWLfzuR12QsNvgQWzrzKSf7YRBNrRXK71vfq12BbyxTLFEZBWfnHqezBVGQiNLfqeuywZHgstMCcS44TXfb2',
    );
  });
});
