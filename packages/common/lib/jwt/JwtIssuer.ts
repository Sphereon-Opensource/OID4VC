import { JWK, JwtHeader, JwtPayload, JwtProtectionMethod, SigningAlgo } from '..';

export interface JwtIssuerBase {
  method: JwtProtectionMethod;
  /**
   * Additional options for the issuance context
   */
  options?: Record<string, unknown>;
}

export interface JwtIssuerDid extends JwtIssuerBase {
  method: 'did';
  didUrl: string;
  alg: SigningAlgo | string;
}

export interface JwtIssuerX5c extends JwtIssuerBase {
  method: 'x5c';
  alg: SigningAlgo | string;

  /**
   *
   * Array of base64-encoded certificate strings in the DER-format.
   *
   * The certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate.
   */
  x5c: Array<string>;

  /**
   * The issuer jwt
   *
   * This value will be used as the iss value of the issue jwt.
   * It is also used as the client_id.
   * And will also be set as the redirect_uri
   *
   * It must match an entry in the x5c certificate leaf entry dnsName / uriName
   */
  issuer: string;
}

export interface JwtIssuerJwk extends JwtIssuerBase {
  method: 'jwk';
  alg: SigningAlgo | string;
  jwk: JWK;
}

export interface JwtIssuerCustom extends JwtIssuerBase {
  method: 'custom';
}

export type JwtIssuer = JwtIssuerDid | JwtIssuerX5c | JwtIssuerJwk | JwtIssuerCustom;

export interface JwtIssuanceContextBase {
  type: string;
}

export type CreateJwtCallback<T extends JwtIssuer & JwtIssuanceContextBase> = (
  jwtIssuer: T,
  jwt: { header: JwtHeader; payload: JwtPayload },
) => Promise<string>;
