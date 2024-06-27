import { AccessTokenRequest, AccessTokenRequestOpts, Jwt, OpenId4VCIVersion } from '@sphereon/oid4vci-common';
import { v4 } from 'uuid';

import { ProofOfPossessionBuilder } from '../ProofOfPossessionBuilder';

export const createJwtBearerClientAssertion = async (
  request: Partial<AccessTokenRequest>,
  opts: AccessTokenRequestOpts & {
    version?: OpenId4VCIVersion;
  },
): Promise<void> => {
  const { asOpts } = opts;
  if (asOpts?.clientOpts?.clientAssertionType === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer') {
    if (!request.client_id) {
      throw Error(`Not client_id supplied, but client-assertion jwt-bearer requested.`);
    } else if (!asOpts.clientOpts.kid) {
      throw Error(`No kid supplied, but client-assertion jwt-bearer requested.`);
    } else if (!asOpts.clientOpts.signCallbacks) {
      throw Error(`No sign callback supplied, but client-assertion jwt-bearer requested.`);
    }
    const jwt: Jwt = {
      header: {
        typ: 'JWT',
        kid: asOpts.clientOpts.kid,
        alg: asOpts.clientOpts.alg ?? 'ES256',
      },
      payload: {
        iss: request.client_id,
        sub: request.client_id,
        aud: opts.credentialIssuer,
        jti: v4(),
        exp: Date.now() / 1000 + 60,
        iat: Date.now() / 1000 - 60,
      },
    };
    const pop = await ProofOfPossessionBuilder.fromJwt({
      jwt,
      callbacks: asOpts.clientOpts.signCallbacks,
      version: opts.version ?? OpenId4VCIVersion.VER_1_0_13,
      mode: 'jwt',
    }).build();
    request.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    request.client_assertion = pop.jwt;
  }
};
