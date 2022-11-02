import { JWTHeaderParameters } from 'jose';
import { v4 as uuidv4 } from 'uuid';

import { CredentialRequestClient } from '../CredentialRequestClient';
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
export async function createProofOfPossession(opts: ProofOfPossessionOpts, client: CredentialRequestClient): Promise<ProofOfPossession> {
  if (!opts.proofOfPossessionCallback || !opts.proofOfPossessionCallbackArgs) {
    throw new Error(BAD_PARAMS);
  }
  const signerArgs = setJWSDefaults(opts.proofOfPossessionCallbackArgs, client);
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

function setJWSDefaults(args: ProofOfPossessionCallbackArgs, client: CredentialRequestClient): { header: JWTHeader; payload: JWTPayload } {
  const now = +new Date();
  if (!client) {
    throw new Error('No client provided');
  }
  const aud = client._issuanceRequestOpts.credentialEndpoint ? client._issuanceRequestOpts.credentialEndpoint : args.payload.aud;
  if (!aud) {
    throw new Error('No issuer url provided');
  }
  if (!args.kid) {
    throw new Error('No kid provided');
  }
  const iss = client._issuanceRequestOpts.clientId ? client._issuanceRequestOpts.clientId : args.payload.iss;
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
    kid: args.kid,
  };
  args.payload = { ...defaultPayload, ...args.payload };
  args.header = { ...defaultHeader, ...args.header };
  return args;
}
