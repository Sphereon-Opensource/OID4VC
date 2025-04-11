import { JwtHeader as jwtDecodeJwtHeader, JwtPayload as jwtDecodePayload } from 'jwt-decode';

import { JWK } from './Jwk.types';

export type JwtHeader = jwtDecodeJwtHeader & {
  alg?: string;
  x5c?: string[];
  kid?: string;
  jwk?: JWK;
  jwt?: string;
} & Record<string, unknown>;

export type JwtPayload = jwtDecodePayload & {
  client_id?: string;
  nonce?: string;
  request_uri?: string;
  client_id_scheme?: string;
} & Record<string, unknown>;

export enum SigningAlgo {
  EDDSA = 'EdDSA',
  RS256 = 'RS256',
  PS256 = 'PS256',
  ES256 = 'ES256',
  ES256K = 'ES256K',
}
