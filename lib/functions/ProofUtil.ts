import Debug from 'debug';
import { JWTHeaderParameters } from 'jose';

import { BAD_PARAMS, JWS_NOT_VALID, Jwt, JWTPayload, ProofOfPossession, ProofOfPossessionCallbacks, ProofType } from '../types';

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
 * @param kid: the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound to
 * @param endpointMetadata
 *  - Mandatory for signing the ProofOfPossession
 * @param jwtArgs
 * @param clientId
 *  - Optional, clientId of the party requesting the credential
 */
export const createProofOfPossession = async (
  callbacks: ProofOfPossessionCallbacks,
  jwtProps?: JwtProps,
  existingJwt?: Jwt
): Promise<ProofOfPossession> => {
  if (!callbacks.signCallback) {
    debug(`no jwt signer callback or arguments supplied!`);
    throw new Error(BAD_PARAMS);
  }
  const signerArgs = createJWT(jwtProps, existingJwt);
  const jwt = await callbacks.signCallback(signerArgs, signerArgs.header.kid);
  const proof = {
    proof_type: ProofType.JWT,
    jwt,
  };

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
  kid?: string;
  issuer?: string;
  clientId?: string;
  alg?: string;
  jti?: string;
  nonce?: string;
}

const createJWT = (jwtProps?: JwtProps, existingJwt?: Jwt): Jwt => {
  const aud = getJwtProperty('aud', true, jwtProps.issuer, existingJwt?.payload?.aud);
  const iss = getJwtProperty('iss', false, jwtProps.clientId, existingJwt?.payload?.iss);
  const jti = getJwtProperty('jti', false, jwtProps.jti, existingJwt?.payload?.jti);
  const nonce = getJwtProperty('nonce', true, jwtProps.nonce, existingJwt?.payload?.nonce);
  const alg = getJwtProperty('alg', false, jwtProps.alg, existingJwt?.header?.alg, 'ES256');
  const kid = getJwtProperty('kid', true, jwtProps.kid, existingJwt?.header?.kid);
  const jwt = existingJwt ? existingJwt : {};
  const now = +new Date();
  const jwtPayload: Partial<JWTPayload> = {
    aud,
    iat: jwt.payload?.iat ? jwt.payload.iat : now / 1000 - 60, // Let's ensure we subtract 60 seconds for potential time offsets
    exp: jwt.payload?.exp ? jwt.payload.exp : now / 1000 + 10 * 60,
    nonce,
    ...(iss ? { iss } : {}),
    ...(jti ? { jti } : {}),
  };

  const jwtHeader: JWTHeaderParameters = {
    typ: 'JWT',
    alg,
    kid,
  };
  return {
    payload: { ...jwt.payload, ...jwtPayload },
    header: { ...jwt.header, ...jwtHeader },
  };
};

const getJwtProperty = (
  propertyName: string,
  required: boolean,
  option?: string,
  jwtProperty?: string,
  defaultValue?: string
): string | undefined => {
  if (option && jwtProperty && option !== jwtProperty) {
    throw Error(`Cannot have a property '${propertyName}' with value '${option}' and different JWT value '${jwtProperty}' at the same time`);
  }
  let result = jwtProperty ? jwtProperty : option;
  if (!result) {
    if (required) {
      throw Error(`No ${propertyName} property provided either in a JWT or as option`);
    }
    result = defaultValue;
  }
  return result;
};
