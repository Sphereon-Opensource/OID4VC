import { uuidv4 } from '@sphereon/common';
import { AccessTokenRequest, AccessTokenRequestOpts, Jwt, OpenId4VCIVersion } from '@sphereon/oid4vci-common';

import { ProofOfPossessionBuilder } from '../ProofOfPossessionBuilder';

export const createJwtBearerClientAssertion = async (
  request: Partial<AccessTokenRequest>,
  opts: AccessTokenRequestOpts & {
    version?: OpenId4VCIVersion;
  },
): Promise<void> => {
  const { asOpts, credentialIssuer } = opts;
  if (asOpts?.clientOpts?.clientAssertionType === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
    const { clientId = request.client_id, signCallbacks, alg } = asOpts.clientOpts;
    let { kid } = asOpts.clientOpts;
    if (!clientId) {
      return Promise.reject(Error(`Not client_id supplied, but client-assertion jwt-bearer requested.`));
    } else if (!kid) {
      return Promise.reject(Error(`No kid supplied, but client-assertion jwt-bearer requested.`));
    } else if (typeof signCallbacks?.signCallback !== 'function') {
      return Promise.reject(Error(`No sign callback supplied, but client-assertion jwt-bearer requested.`));
    } else if (!credentialIssuer) {
      return Promise.reject(Error(`No credential issuer supplied, but client-assertion jwt-bearer requested.`));
    }
    if (clientId.startsWith('http') && kid.includes('#')) {
      kid = kid.split('#')[1];
    }
    const jwt: Jwt = {
      header: {
        typ: 'JWT',
        kid,
        alg: alg ?? 'ES256',
      },
      payload: {
        iss: clientId,
        sub: clientId,
        aud: credentialIssuer,
        jti: uuidv4(),
        exp: Date.now() / 1000 + 60,
        iat: Date.now() / 1000 - 60,
      },
    };
    const pop = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: signCallbacks,
      version: opts.version ?? OpenId4VCIVersion.VER_1_0_13,
      mode: 'JWT',
    }).build();
    request.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    request.client_assertion = pop.jwt;
  }
};
