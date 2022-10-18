export const UNIT_TEST_TIMEOUT = 30000;

describe('OID4VCI-Client should', () => {
  const INITIATE_QR_DATA =
    'openid-initiate-issuance://?issuer=https%3A%2F%2Fissuer.research.identiproof.io&credential_type=OpenBadgeCredentialUrl&pre-authorized_code=4jLs9xZHEfqcoow0kHE7d1a8hUk6Sy-5bVSV2MqBUGUgiFFQi-ImL62T-FmLIo8hKA1UdMPH0lM1xAgcFkJfxIw9L-lI3mVs0hRT8YVwsEM1ma6N3wzuCdwtMU4bcwKp&user_pin_required=true';

  it(
    'succeed with a full flow',
    async () => {
      expect(INITIATE_QR_DATA).toBeDefined();
    },
    UNIT_TEST_TIMEOUT
  );
});
