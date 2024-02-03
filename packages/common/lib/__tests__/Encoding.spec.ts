import { convertURIToJsonObject } from '../functions';

import { UNIT_TEST_TIMEOUT } from './CredentialOfferUtil.spec';

describe('URI to json enconding', () => {
  const CREDENTIAL_OFFER_CODE = 'openid-credential-offer://code=1234-1234-1234';

  it(
    'should get code from auth-code redirect URI',
    async () => {
      expect(convertURIToJsonObject(CREDENTIAL_OFFER_CODE)).toEqual({ code: '1234-1234-1234' });
    },
    UNIT_TEST_TIMEOUT,
  );
});
