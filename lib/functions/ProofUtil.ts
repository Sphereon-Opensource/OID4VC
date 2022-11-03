import { JWTHeaderParameters } from 'jose';

import {
  BAD_PARAMS,
  EndpointMetadata,
  JWS_NOT_VALID,
  JWTHeader,
  JWTPayload,
  ProofOfPossession,
  ProofOfPossessionArgs,
  ProofOfPossessionCallbackArgs,
  ProofType,
} from '../types';

/**
 *
 * @param opts: ProofOfPossessionOpts
 *  - proofOfPossessionCallback: JWTSignerCallback
 *    Mandatory if you want to create (sign) ProofOfPossession
 *  - proofOfPossessionVerifierCallback?: JWTVerifyCallback
 *    If exists, verifies the ProofOfPossession
 *  - proofOfPossessionCallbackArgs: ProofOfPossessionCallbackArgs
 *    arguments needed for signing ProofOfPossession
 * @param endpointMetadata
 *  - Mandatory for signing the ProofOfPossession
 * @param clientId
 *  - Optional, clientId of the party requesting the credential
 */
export async function createProofOfPossession(
  opts: ProofOfPossessionArgs,
  endpointMetadata: EndpointMetadata,
  clientId?: string
): Promise<ProofOfPossession> {
  if (!opts.proofOfPossessionCallback || !opts.proofOfPossessionCallbackArgs) {
    throw new Error(BAD_PARAMS);
  }
  const signerArgs = setJWSDefaults(opts.proofOfPossessionCallbackArgs, endpointMetadata, clientId);
  const jwt = await opts.proofOfPossessionCallback({ ...signerArgs, kid: opts.proofOfPossessionCallbackArgs.kid });
  partiallyValidateJWS(jwt);
  const proof = {
    proof_type: ProofType.JWT,
    jwt,
  };
  if (opts.proofOfPossessionVerifierCallback) {
    await opts.proofOfPossessionVerifierCallback({ jwt, kid: opts.proofOfPossessionCallbackArgs.kid });
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
  endpointMetadata: EndpointMetadata,
  clientId?: string
): { header: JWTHeader; payload: JWTPayload } {
  const now = +new Date();
  if (!endpointMetadata) {
    throw new Error('No endpointMetadata provided');
  }
  const aud = endpointMetadata.issuer ? endpointMetadata.issuer : args.payload.aud;
  if (!aud) {
    throw new Error('No issuer url provided');
  }
  if (!args.kid) {
    throw new Error('No kid provided');
  }
  const iss = clientId ? clientId : args.payload.iss;
  if (!iss) {
    throw new Error('No clientId provided');
  }
  const defaultPayload: Partial<JWTPayload> = {
    aud,
    iss,
    iat: args.payload.iat ? args.payload.iat : now / 1000 - 60, // Let's ensure we subtract 60 seconds for potential time offsets
    exp: args.payload.exp ? args.payload.exp : now / 1000 + 10 * 60,
  };
  if (args.payload.jti) {
    defaultPayload.jti = args.payload.jti;
  }
  const defaultHeader: JWTHeaderParameters = {
    alg: args.header.alg ? args.header.alg : 'ES256',
    typ: 'JWT',
    kid: args.kid,
  };
  args.payload = { ...defaultPayload, ...args.payload };
  args.header = { ...defaultHeader, ...args.header };
  return args;
}
