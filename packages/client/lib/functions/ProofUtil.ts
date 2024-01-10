import {
  BAD_PARAMS,
  BaseJWK,
  JWK,
  JWS_NOT_VALID,
  Jwt,
  JWTHeader,
  JWTPayload,
  ProofOfPossession,
  ProofOfPossessionCallbacks,
  Typ,
} from '@sphereon/oid4vci-common';
import Debug from 'debug';

const debug = Debug('sphereon:openid4vci:token');

/**
 *
 *  - proofOfPossessionCallback: JWTSignerCallback
 *    Mandatory if you want to create (sign) ProofOfPossession
 *  - proofOfPossessionVerifierCallback?: JWTVerifyCallback
 *    If exists, verifies the ProofOfPossession
 *  - proofOfPossessionCallbackArgs: ProofOfPossessionCallbackArgs
 *    arguments needed for signing ProofOfPossession
 * @param callbacks:
 *    - proofOfPossessionCallback: JWTSignerCallback
 *      Mandatory to create (sign) ProofOfPossession
 *    - proofOfPossessionVerifierCallback?: JWTVerifyCallback
 *      If exists, verifies the ProofOfPossession
 * @param jwtProps
 * @param existingJwt
 *  - Optional, clientId of the party requesting the credential
 */
export const createProofOfPossession = async <DIDDoc>(
  callbacks: ProofOfPossessionCallbacks<DIDDoc>,
  jwtProps?: JwtProps,
  existingJwt?: Jwt,
): Promise<ProofOfPossession> => {
  if (!callbacks.signCallback) {
    debug(`no jwt signer callback or arguments supplied!`);
    throw new Error(BAD_PARAMS);
  }

  const signerArgs = createJWT(jwtProps, existingJwt);
  const jwt = await callbacks.signCallback(signerArgs, signerArgs.header.kid);
  const proof = {
    proof_type: 'jwt',
    jwt,
  } as ProofOfPossession;

  try {
    partiallyValidateJWS(jwt);
    if (callbacks.verifyCallback) {
      debug(`Calling supplied verify callback....`);
      await callbacks.verifyCallback({ jwt, kid: signerArgs.header.kid });
      debug(`Supplied verify callback return success result`);
    }
  } catch {
    debug(`JWS was not valid`);
    throw new Error(JWS_NOT_VALID);
  }
  debug(`Proof of Possession JWT:\r\n${jwt}`);
  return proof;
};

const partiallyValidateJWS = (jws: string): void => {
  if (jws.split('.').length !== 3 || !jws.startsWith('ey')) {
    throw new Error(JWS_NOT_VALID);
  }
};

export interface JwtProps {
  typ?: Typ;
  kid?: string;
  jwk?: JWK;
  issuer?: string;
  clientId?: string;
  alg?: string;
  jti?: string;
  nonce?: string;
}

const createJWT = (jwtProps?: JwtProps, existingJwt?: Jwt): Jwt => {
  const aud = getJwtProperty<string | string[]>('aud', true, jwtProps?.issuer, existingJwt?.payload?.aud);
  const iss = getJwtProperty<string>('iss', false, jwtProps?.clientId, existingJwt?.payload?.iss);
  const jti = getJwtProperty<string>('jti', false, jwtProps?.jti, existingJwt?.payload?.jti);
  const typ = getJwtProperty<string>('typ', true, jwtProps?.typ, existingJwt?.header?.typ, 'jwt');
  const nonce = getJwtProperty<string>('nonce', false, jwtProps?.nonce, existingJwt?.payload?.nonce); // Officially this is required, but some implementations don't have it
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const alg = getJwtProperty<string>('alg', false, jwtProps?.alg, existingJwt?.header?.alg, 'ES256')!;
  const kid = getJwtProperty<string>('kid', false, jwtProps?.kid, existingJwt?.header?.kid);
  const jwk = getJwtProperty<BaseJWK>('jwk', false, jwtProps?.jwk, existingJwt?.header?.jwk);
  const jwt: Partial<Jwt> = existingJwt ? existingJwt : {};
  const now = +new Date();
  const jwtPayload: Partial<JWTPayload> = {
    aud,
    iat: jwt.payload?.iat ? jwt.payload.iat : now / 1000 - 60, // Let's ensure we subtract 60 seconds for potential time offsets
    exp: jwt.payload?.exp ? jwt.payload.exp : now / 1000 + 10 * 60,
    nonce,
    ...(iss ? { iss } : {}),
    ...(jti ? { jti } : {}),
  };

  const jwtHeader: JWTHeader = {
    typ,
    alg,
    kid,
    jwk,
  };
  return {
    payload: { ...jwt.payload, ...jwtPayload },
    header: { ...jwt.header, ...jwtHeader },
  };
};

const getJwtProperty = <T>(propertyName: string, required: boolean, option?: string | JWK, jwtProperty?: T, defaultValue?: T): T | undefined => {
  if (typeof option === 'string' && option && jwtProperty && option !== jwtProperty) {
    throw Error(`Cannot have a property '${propertyName}' with value '${option}' and different JWT value '${jwtProperty}' at the same time`);
  }
  let result = (jwtProperty ? jwtProperty : option) as T | undefined;
  if (!result) {
    if (required) {
      throw Error(`No ${propertyName} property provided either in a JWT or as option`);
    }
    result = defaultValue;
  }
  return result;
};
