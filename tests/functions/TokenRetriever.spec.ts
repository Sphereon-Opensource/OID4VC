
import {
  AccessTokenIssuanceRequest,
  AuthorizationExchange,
  AuthorizationExchangeMetaData,
  AuthorizationGrantResponse,
  AuthorizationRequest,
  Builder,
  ClientType,
  ExchangeStep,
  GrantTypes,
  TokenRetriever,
} from '../../src';
import { UNIT_TEST_TIMEOUT } from '../IT.spec';

describe('TokenRetriever should', () => {
  it(
    'get Access Token without resulting in errors',
    async () => {
      const tokenRetriever: TokenRetriever = new TokenRetriever();

      const accessTokenIssuanceRequest: AccessTokenIssuanceRequest = Builder<AccessTokenIssuanceRequest>()
        .grant_type(GrantTypes['PRE-AUTHORIZED'])
        ['pre-authorized_code']('pre-authorized_code2022-10-11')
        .build();

      const authRequest: AuthorizationRequest = Builder<AuthorizationRequest>().build();
      const authResponse: AuthorizationGrantResponse = Builder<AuthorizationGrantResponse>().build();

      const authorizationExchange: AuthorizationExchange = Builder<AuthorizationExchange>()
        .url(new URL('https://sphereonJUnitIssuer2022-10-11_00.com/auth'))
        .request(authRequest)
        .response(authResponse)
        .build();

      const exchanges: Map<ExchangeStep, AuthorizationExchange> = new Map<ExchangeStep, AuthorizationExchange>();
      exchanges.set(ExchangeStep.AUTHORIZATION, authorizationExchange);
      const authorizationExchangeMetaData: AuthorizationExchangeMetaData = Builder<AuthorizationExchangeMetaData>()
        .isAuthenticatingWithAuthorizationServer(true)
        .client_type(ClientType.CONFIDENTIAL)
        .exchanges(exchanges)
        .build();

      expect(tokenRetriever.getAccessToken(accessTokenIssuanceRequest, authorizationExchangeMetaData)).toEqual(null);
    },
    UNIT_TEST_TIMEOUT
  );
});
