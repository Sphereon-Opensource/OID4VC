import { determineSpecVersionFromURI } from '../functions';
import { OpenId4VCIVersion } from '../types';

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
      expect(determineSpecVersionFromURI(CREDENTIAL_OFFER_QR_V11)).toEqual(OpenId4VCIVersion.VER_1_0_12);
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
      expect(determineSpecVersionFromURI('test://uri')).toEqual(OpenId4VCIVersion.VER_1_0_12);
    },
    UNIT_TEST_TIMEOUT,
  );
});
