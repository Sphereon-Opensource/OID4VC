import { JWTHeaderParameters } from 'jose';
import { v4 as uuidv4 } from 'uuid';

import {
  BAD_PARAMS,
  JWS_NOT_VALID,
  JWTHeader,
  JWTPayload,
  ProofOfPossession,
  ProofOfPossessionCallbackArgs,
  ProofOfPossessionOpts,
  ProofType,
} from '../types';

/**
 * createProofOfPossession creates and returns the ProofOfPossession object
 * @param opts
 *         - jwtSignerArgs: The arguments to create the signature
 *         - jwtSignerCallback: function to sign the proof
 *         - jwtVerifyCallback: function to verify if JWT is valid
 */
export async function createProofOfPossession(opts: ProofOfPossessionOpts): Promise<ProofOfPossession> {
  if (!opts.proofOfPossessionCallback || !opts.proofOfPossessionCallbackArgs) {
    throw new Error(BAD_PARAMS);
  }
  const signerArgs = setJWSDefaults(
    opts.proofOfPossessionCallbackArgs,
    opts.proofOfPossessionCallbackArgs.kid,
    opts.proofOfPossessionCallbackArgs.issuerURL,
    opts.proofOfPossessionCallbackArgs.clientId
  );
  const jwt = await opts.proofOfPossessionCallback(signerArgs);
  partiallyValidateJWS(jwt);
  const proof = {
    proof_type: ProofType.JWT,
    jwt,
  };
  if (opts.proofOfPossessionVerifierCallback) {
    await opts.proofOfPossessionVerifierCallback({ jwt, publicKey: opts.proofOfPossessionCallbackArgs.publicKey });
  }
  return proof;
}

function partiallyValidateJWS(jws: string): void {
  if (jws.split('.').length !== 3 || !jws.startsWith('ey')) {
    throw new Error(JWS_NOT_VALID);
  }
}

function setJWSDefaults(
  args: ProofOfPossessionCallbackArgs,
  kid: string,
  issuerUrl: string,
  clientId?: string
): { header: JWTHeader; payload: JWTPayload } {
  const now = +new Date();
  const aud = args.payload.aud ? args.payload.aud : issuerUrl;
  if (!aud) {
    throw new Error('No issuer url provided');
  }
  const proof_kid = kid ? kid : args.header.kid;
  if (!kid) {
    throw new Error('No kid provided');
  }
  const iss = args.payload.iss ? args.payload.iss : clientId;
  if (!iss) {
    throw new Error('No clientId provided');
  }
  const jti = args.payload.jti ? args.payload.jti : uuidv4();
  const defaultPayload: Partial<JWTPayload> = {
    jti,
    aud,
    iss,
    iat: args.payload.iat ? args.payload.iat : now / 1000 - 60, // Let's ensure we subtract 60 seconds for potential time offsets
    exp: args.payload.exp ? args.payload.exp : now / 1000 + 10 * 60,
  };
  const defaultHeader: JWTHeaderParameters = {
    alg: 'ES256',
    typ: 'JWT',
    kid: proof_kid,
  };
  args.payload = { ...defaultPayload, ...args.payload };
  args.header = { ...defaultHeader, ...args.header };
  return args;
}
