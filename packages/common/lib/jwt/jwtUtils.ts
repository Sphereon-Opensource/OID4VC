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

/**
 * The maximum allowed clock skew time in seconds. If an time based validation
 * is performed against current time (`now`), the validation can be of by the skew
 * time.
 *
 * See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
 */
const DEFAULT_SKEW_TIME = 60;

export function getNowSkewed(now?: number, skewTime?: number) {
  const _now = now ? now : epochTime();
  const _skewTime = skewTime ? skewTime : DEFAULT_SKEW_TIME;

  return {
    nowSkewedPast: _now - _skewTime,
    nowSkewedFuture: _now + _skewTime,
  };
}

/**
 * Returns the current unix timestamp in seconds.
 */
export function epochTime() {
  return Math.floor(Date.now() / 1000);
}

export const BASE64_URL_REGEX = /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/;

export const isJws = (jws: string) => {
  const jwsParts = jws.split('.');
  return jwsParts.length === 3 && jwsParts.every((part) => BASE64_URL_REGEX.test(part));
};
export const isJwe = (jwe: string) => {
  const jweParts = jwe.split('.');
  return jweParts.length === 5 && jweParts.every((part) => BASE64_URL_REGEX.test(part));
};

export const decodeProtectedHeader = (jwt: string) => {
  return jwtDecode(jwt, { header: true });
};

export const decodeJwt = (jwt: string): JwtPayload => {
  return jwtDecode(jwt, { header: false });
};

export const checkExp = (input: {
  exp: number;
  now?: number; // The number of milliseconds elapsed since midnight, January 1, 1970 Universal Coordinated Time (UTC).
  clockSkew?: number;
}) => {
  const { exp, now, clockSkew } = input;
  return exp < (now ?? Date.now() / 1000) - (clockSkew ?? 120);
};
