import { JWTHeaderParameters, JWTPayload } from 'jose';
import sign from 'jwt-encode';

import {
  BAD_PARAMS,
  JWS_NOT_VALID,
  PoPSignInputDecoded,
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
  const signerArgs = setJWSDefaults(opts.proofOfPossessionCallbackArgs, opts.issuerURL, opts.clientId);
  const jwt = await opts.proofOfPossessionCallback(signerArgs);
  partiallyValidateJWS(jwt);
  return {
    proof_type: ProofType.JWT,
    jwt: jwt,
  };
}

function partiallyValidateJWS(jws: string): void {
  if (jws.split('.').length !== 3 || !jws.startsWith('ey')) {
    throw new Error(JWS_NOT_VALID);
  }
}

function setJWSDefaults(args: ProofOfPossessionCallbackArgs, issuerUrl: string, clientId?: string): { header: unknown; payload: unknown } {
  const now = +new Date();
  const aud = args.payload && args.payload['aud'] ? args.payload['aud'] : issuerUrl;
  if (!aud) {
    throw new Error('No issuer url provided');
  }
  const iss = args.payload['iss'] ? args.payload['iss'] : clientId;
  if (!iss) {
    throw new Error('No clientId provided');
  }
  const defaultPayload: Partial<JWTPayload> = {
    aud,
    iss,
    iat: args.payload['iat'] ? args.payload['iat'] : now / 1000 - 60, // Let's ensure we subtract 60 seconds for potential time offsets
    exp: args.payload['exp'] ? args.payload['exp'] : now / 1000 + 10 * 60,
  };
  const defaultHeader: JWTHeaderParameters = {
    alg: 'ES256',
    typ: 'JWT',
  };
  args.payload = { ...defaultPayload, ...(args.payload as unknown as ProofOfPossessionCallbackArgs) };
  args.header = { ...defaultHeader, ...(args.header as unknown as any) };
  return args as unknown as any;
}

export async function encodeProof(popSignInputDecodedArgs: PoPSignInputDecoded): Promise<string> {
  return sign(
    {
      aud: popSignInputDecodedArgs.aud,
      iss: popSignInputDecodedArgs.iss,
      iat: popSignInputDecodedArgs.iat,
      exp: popSignInputDecodedArgs.exp,
      jti: popSignInputDecodedArgs.jti,
    },
    '',
    {
      alg: popSignInputDecodedArgs.signAlgorithm as unknown as any,
      typ: popSignInputDecodedArgs.type as unknown as any,
    }
  );
}
