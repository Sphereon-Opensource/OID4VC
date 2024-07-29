import { jwtDecode } from 'jwt-decode';

import { JwtHeader, JwtPayload } from '..';

export type JwtType = 'id-token' | 'request-object' | 'verifier-attestation' | 'dpop';

export type JwtProtectionMethod = 'did' | 'x5c' | 'jwk' | 'openid-federation' | 'custom';

export function parseJWT<Header = JwtHeader, Payload = JwtPayload>(jwt: string) {
  const header = jwtDecode<Header>(jwt, { header: true });
  const payload = jwtDecode<Payload>(jwt, { header: false });

  if (!payload || !header) {
    throw new Error('Jwt Payload and/or Header could not be parsed');
  }
  return { header, payload };
}
