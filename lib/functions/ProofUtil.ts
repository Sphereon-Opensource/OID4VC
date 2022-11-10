import Debug from 'debug';

import { BAD_PARAMS, JWS_NOT_VALID, JWTHeader, JWTPayload, JWTSignerArgs, ProofOfPossession, ProofOfPossessionOpts, ProofType } from '../types';

const debug = Debug('sphereon:oid4vci:token');

/**
 *
 *  - proofOfPossessionCallback: JWTSignerCallback
 *    Mandatory if you want to create (sign) ProofOfPossession
 *  - proofOfPossessionVerifierCallback?: JWTVerifyCallback
 *    If exists, verifies the ProofOfPossession
 *  - proofOfPossessionCallbackArgs: ProofOfPossessionCallbackArgs
 *    arguments needed for signing ProofOfPossession
 * @param args:
 *    - proofOfPossessionCallback: JWTSignerCallback
 *      Mandatory to create (sign) ProofOfPossession
 *    - proofOfPossessionVerifierCallback?: JWTVerifyCallback
 *      If exists, verifies the ProofOfPossession
 * @param kid: the kid refers to a DID URL which identifies a particular key in the DID Document that the Credential shall be bound t
 * @param endpointMetadata
 *  - Mandatory for signing the ProofOfPossession
 * @param jwtArgs
 * @param clientId
 *  - Optional, clientId of the party requesting the credential
 */
export async function createProofOfPossession(
  args: ProofOfPossessionArgs,
  kid: string,
  endpointMetadata: EndpointMetadata,
  jwtArgs?: JwtArgs,
  clientId?: string
): Promise<ProofOfPossession> {
  if (!args.proofOfPossessionCallback) {
    debug(`no jwt signer callback or arguments supplied!`);
    throw new Error(BAD_PARAMS);
  }
  const signerArgs = createJWT(kid, endpointMetadata, jwtArgs, clientId);
  const jwt = await args.proofOfPossessionCallback(signerArgs, kid);
  partiallyValidateJWS(jwt);
  const proof = {
    proof_type: ProofType.JWT,
    jwt,
  };
  try {
  if (args.proofOfPossessionVerifierCallback) {
    debug(`Calling supplied verify callback....`);
    await args.proofOfPossessionVerifierCallback({ jwt, kid: kid });
    debug(`Supplied verify callback return success result`);
  }} catch {
    debug(`JWS was not valid`);
    throw new Error(JWS_NOT_VALID);
  }
  debug(`Proof of Possession JWT:\r\n${jwt}`);
  return proof;
}

function partiallyValidateJWS(jws: string): void {
  if (jws.split('.').length !== 3 || !jws.startsWith('ey')) {
    throw new Error(JWS_NOT_VALID);
  }
}

function createJWT(kid: string, endpointMetadata: EndpointMetadata, jwtArgs?: JwtArgs, clientId?: string): JwtArgs {
  if (!jwtArgs) {
    jwtArgs = {
      header: {
        alg: Alg.ES256,
        typ: 'JWT',
        kid: kid,
      },
      payload: {},
    };
  }
  const now = +new Date();
  const aud = jwtArgs.payload?.aud ? jwtArgs.payload.aud : endpointMetadata.issuer;
  if (!aud) {
    throw new Error('No issuer url provided');
  }
  const defaultPayload: Partial<JWTPayload> = {
    aud,
    iat: jwtArgs.payload.iat ? jwtArgs.payload.iat : now / 1000 - 60, // Let's ensure we subtract 60 seconds for potential time offsets
    exp: jwtArgs.payload.exp ? jwtArgs.payload.exp : now / 1000 + 10 * 60,
  };
  const iss = clientId ? clientId : jwtArgs.payload.iss ? jwtArgs.payload.iss : null;
  if (iss) {
    defaultPayload.iss = iss;
  }
  if (jwtArgs.payload.jti) {
    defaultPayload.jti = jwtArgs.payload.jti;
  }
  const defaultHeader: JWTHeaderParameters = {
    alg: jwtArgs.header.alg ? jwtArgs.header.alg : 'ES256',
    typ: 'JWT',
    kid: kid,
  };
  jwtArgs.payload = { ...defaultPayload, ...jwtArgs.payload };
  jwtArgs.header = { ...defaultHeader, ...jwtArgs.header };
  return jwtArgs;
}
