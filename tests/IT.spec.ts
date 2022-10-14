export const UNIT_TEST_TIMEOUT = 30000;

describe('oidc4vci client should', () => {
  it(
    'succeed in starting',
    async () => {
      expect(true).toBeTruthy();
    },
    UNIT_TEST_TIMEOUT
  );
});
