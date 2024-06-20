import Debug from 'debug';
import jwtDecode from 'jwt-decode';

import { PoPMode, VCI_LOG_COMMON } from '..';
import {
  BAD_PARAMS,
  BaseJWK,
  JWK,
  JWS_NOT_VALID,
  Jwt,
  JWTHeader,
  JWTPayload,
  JWTVerifyCallback,
  JwtVerifyResult,
  ProofOfPossession,
  ProofOfPossessionCallbacks,
  Typ,
} from '../types';

const debug = Debug('sphereon:openid4vci:common');

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
  popMode: PoPMode,
  callbacks: ProofOfPossessionCallbacks<DIDDoc>,
  jwtProps?: JwtProps,
  existingJwt?: Jwt,
): Promise<ProofOfPossession> => {
  if (!callbacks.signCallback) {
    debug(`no jwt signer callback or arguments supplied!`);
    throw new Error(BAD_PARAMS);
  }

  const signerArgs = createJWT(popMode, jwtProps, existingJwt);
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

export const isJWS = (token: string): boolean => {
  try {
    partiallyValidateJWS(token);
    return true;
  } catch (e) {
    return false;
  }
};

export const extractBearerToken = (authorizationHeader?: string): string | undefined => {
  return authorizationHeader ? /Bearer (.*)/i.exec(authorizationHeader)?.[1] : undefined;
};

export const validateJWT = async (
  jwt?: string,
  opts?: { kid?: string; accessTokenVerificationCallback?: JWTVerifyCallback<never> },
): Promise<JwtVerifyResult<any>> => {
  if (!jwt) {
    throw Error('No JWT was supplied');
  }

  if (!opts?.accessTokenVerificationCallback) {
    VCI_LOG_COMMON.warning(`No access token verification callback supplied. Access tokens will not be verified, except for a very basic check`);
    partiallyValidateJWS(jwt);
    const header = jwtDecode<JWTHeader>(jwt, { header: true });
    const payload = jwtDecode<JWTPayload>(jwt, { header: false });
    return {
      jwt: { header, payload } satisfies Jwt,
      ...header,
      ...payload,
    };
  } else {
    return await opts.accessTokenVerificationCallback({ jwt, kid: opts.kid });
  }
};

export interface JwtProps {
  typ?: Typ;
  kid?: string;
  jwk?: JWK;
  x5c?: string[];
  aud?: string | string[];
  issuer?: string;
  clientId?: string;
  alg?: string;
  jti?: string;
  nonce?: string;
}

const createJWT = (mode: PoPMode, jwtProps?: JwtProps, existingJwt?: Jwt): Jwt => {
  const aud =
    mode === 'pop'
      ? getJwtProperty<string | string[]>('aud', true, jwtProps?.issuer, existingJwt?.payload?.aud)
      : getJwtProperty<string | string[]>('aud', false, jwtProps?.aud, existingJwt?.payload?.aud);
  const iss =
    // mode === 'pop'
       getJwtProperty<string>('iss', false, jwtProps?.clientId, existingJwt?.payload?.iss)
      // : getJwtProperty<string>('iss', false, jwtProps?.issuer, existingJwt?.payload?.iss);
  const client_id = mode === 'jwt' ? getJwtProperty<string>('client_id', false, jwtProps?.clientId, existingJwt?.payload?.client_id) : undefined;
  const jti = getJwtProperty<string>('jti', false, jwtProps?.jti, existingJwt?.payload?.jti);
  const typ = getJwtProperty<string>('typ', true, jwtProps?.typ, existingJwt?.header?.typ, 'openid4vci-proof+jwt');
  const nonce = getJwtProperty<string>('nonce', false, jwtProps?.nonce, existingJwt?.payload?.nonce); // Officially this is required, but some implementations don't have it
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const alg = getJwtProperty<string>('alg', false, jwtProps?.alg, existingJwt?.header?.alg, 'ES256')!;
  const kid = getJwtProperty<string>('kid', false, jwtProps?.kid, existingJwt?.header?.kid);
  const jwk = getJwtProperty<BaseJWK>('jwk', false, jwtProps?.jwk, existingJwt?.header?.jwk);
  const x5c = getJwtProperty<string[]>('x5c', false, jwtProps?.x5c, existingJwt?.header.x5c);
  const jwt: Partial<Jwt> = existingJwt ? existingJwt : {};
  const now = +new Date();
  const jwtPayload: Partial<JWTPayload> = {
    ...(aud && { aud }),
    iat: jwt.payload?.iat ?? Math.round(now / 1000 - 60), // Let's ensure we subtract 60 seconds for potential time offsets
    exp: jwt.payload?.exp ?? Math.round(now / 1000 + 10 * 60),
    nonce,
    ...(client_id && { client_id }),
    ...(iss && { iss }),
    ...(jti && { jti }),
  };

  const jwtHeader: JWTHeader = {
    typ,
    alg,
    ...(kid && { kid }),
    ...(jwk && { jwk }),
    ...(x5c && { x5c }),
  };
  return {
    payload: { ...jwt.payload, ...jwtPayload },
    header: { ...jwt.header, ...jwtHeader },
  };
};

const getJwtProperty = <T>(
  propertyName: string,
  required: boolean,
  option?: string | string[] | JWK,
  jwtProperty?: T,
  defaultValue?: T,
): T | undefined => {
  if ((typeof option === 'string' || Array.isArray(option)) && option && jwtProperty && option !== jwtProperty) {
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
