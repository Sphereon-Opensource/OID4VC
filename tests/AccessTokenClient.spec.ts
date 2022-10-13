
import {
  AccessTokenClient,
  AccessTokenIssuanceRequest,
  AccessTokenResponse,
  AuthorizationExchange,
  AuthorizationExchangeMetaData,
  AuthorizationGrantResponse,
  Builder,
  ClientType,
  ExchangeStep,
  GrantTypes,
  IssuanceInitiationRequestPayload
} from '../src';

import { UNIT_TEST_TIMEOUT } from './IT.spec';

describe('AccessTokenClient should', () => {
  it(
    'get Access Token without resulting in errors',
    async () => {
      const tokenRetriever: AccessTokenClient = new AccessTokenClient();

      const accessTokenIssuanceRequest: AccessTokenIssuanceRequest = Builder<AccessTokenIssuanceRequest>()
        .grant_type(GrantTypes['PRE-AUTHORIZED'])
        .pre_authorized_code('pre-authorized_code2022-10-11')
        .build();

      const authRequest: IssuanceInitiationRequestPayload = Builder<IssuanceInitiationRequestPayload>()
        .issuer('https://sphereonJuntiPreAuthIssuerHost2022-10-1300.com')
        .build();

      const authResponse: AuthorizationGrantResponse = Builder<AuthorizationGrantResponse>().build();

      const authorizationExchange: AuthorizationExchange = Builder<AuthorizationExchange>()
        .url(new URL('https://sphereonJUnitIssuer2022-10-11_00.com/auth'))
        .request(authRequest)
        .response(authResponse)
        .build();

      const exchanges: Map<ExchangeStep, AuthorizationExchange> = new Map<ExchangeStep, AuthorizationExchange>();
      exchanges.set(ExchangeStep.AUTHORIZATION, authorizationExchange);
      const authorizationExchangeMetaData: AuthorizationExchangeMetaData = Builder<AuthorizationExchangeMetaData>()
        .client_type(ClientType.CONFIDENTIAL)
        .exchanges(exchanges)
        .build();

      const accessTokenResponse:AccessTokenResponse = await tokenRetriever.acquireAccessToken(accessTokenIssuanceRequest, authorizationExchangeMetaData);
      expect(accessTokenResponse).toEqual(null);
    },
    UNIT_TEST_TIMEOUT
  );
});
