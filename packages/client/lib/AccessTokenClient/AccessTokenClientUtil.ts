import { OpenId4VCIVersion } from '@sphereon/openid4vci-common';

import { AccessTokenClient } from './AccessTokenClient';
import { CredentialOfferAccessTokenClient } from './CredentialOfferAccessTokenClient';
import { IssuanceInitiationAccessTokenClient } from './IssuanceInitiationAccessTokenClient';

export class AccessTokenClientUtil {
  public static determineAccessTokenClient(openId4VCIVersion: OpenId4VCIVersion): AccessTokenClient {
    if (openId4VCIVersion === OpenId4VCIVersion.VER_9) {
      return new IssuanceInitiationAccessTokenClient();
    }

    return new CredentialOfferAccessTokenClient();
  }
}
