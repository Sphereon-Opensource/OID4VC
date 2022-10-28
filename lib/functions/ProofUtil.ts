import { BAD_PARAMS, JWS_NOT_VALID, JWTHeader, JWTPayload, JWTSignerArgs, ProofOfPossession, ProofOfPossessionOpts, ProofType } from '../types';

/**
 * createProofOfPossession creates and returns the ProofOfPossession object
 * @param opts
 *         - jwtSignerArgs: The arguments to create the signature
 *         - jwtSignerCallback: function to sign the proof
 *         - jwtVerifyCallback: function to verify if JWT is valid
 */
export async function createProofOfPossession(opts: ProofOfPossessionOpts): Promise<ProofOfPossession> {
  if (!opts.jwtSignerCallback || !opts.jwtSignerArgs) {
    throw new Error(BAD_PARAMS);
  }
  const signerArgs = setJWSDefaults(opts.jwtSignerArgs, opts.issuerURL, opts.clientId);
  const jwt = await opts.jwtSignerCallback(signerArgs);
  try {
    if (opts.jwtVerifyCallback) {
      const algorithm = opts.jwtSignerArgs.header.alg;
      await opts.jwtVerifyCallback({ jws: jwt, key: opts.jwtSignerArgs.publicKey, algorithms: [algorithm] });
    } else {
      partiallyValidateJWS(jwt);
    }
  } catch {
    throw new Error(JWS_NOT_VALID);
  }
  return {
    proof_type: ProofType.JWT,
    jwt,
  };
}

function partiallyValidateJWS(jws: string): void {
  if (jws.split('.').length !== 3 || !jws.startsWith('ey')) {
    throw new Error(JWS_NOT_VALID);
  }
}

function setJWSDefaults(args: JWTSignerArgs, issuerUrl: string, clientId?: string): JWTSignerArgs {
  const now = +new Date();
  const aud = args.payload.aud ? args.payload.aud : issuerUrl;
  if (!aud) {
    throw new Error('No issuer url provided');
  }
  const iss = args.payload.iss ? args.payload.iss : clientId;
  if (!iss) {
    throw new Error('No clientId provided');
  }
  const defaultPayload: Partial<JWTPayload> = {
    aud,
    iss,
    iat: args.payload.iat ? args.payload.iat : now / 1000 - 60, // Let's ensure we subtract 60 seconds for potential time offsets
    exp: args.payload.exp ? args.payload.exp : now / 1000 + 10 * 60,
  };
  const defaultHeader: JWTHeader = {
    alg: 'ES256',
    typ: 'JWT',
  };
  args.payload = { ...defaultPayload, ...args.payload };
  args.header = { ...defaultHeader, ...args.header };
  return args;
}
