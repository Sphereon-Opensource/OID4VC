import { AuthorizationResponseOpts } from '../authorization-response'
import { JwtProtectionMethod, JwtType } from '../helpers/jwtUtils'

import { JwtHeader, JwtPayload } from './JWT.types'
import { SigningAlgo } from './SIOP.types'

interface JwtIssuerBase {
  method: JwtProtectionMethod
  /**
   * Additional options for the issuance context
   */
  options?: Record<string, unknown>
}

interface JwtIssuanceContextBase extends JwtIssuerBase {
  type: JwtType
}

interface RequestObjectContext extends JwtIssuanceContextBase {
  type: 'request-object'
}

interface IdTokenContext extends JwtIssuanceContextBase {
  type: 'id-token'
  authorizationResponseOpts: AuthorizationResponseOpts
}

export type JwtIssuanceContext = RequestObjectContext | IdTokenContext

interface JwtIssuerDid extends JwtIssuerBase {
  method: 'did'

  didUrl: string
  alg: SigningAlgo
}

interface JwtIssuerX5c extends JwtIssuerBase {
  method: 'x5c'

  /**
   *
   * Array of base64-encoded certificate strings in the DER-format.
   *
   * The certificate containing the public key corresponding to the key used to digitally sign the JWS MUST be the first certificate.
   */
  x5c: Array<string>

  /**
   * The issuer jwt
   *
   * This value will be used as the iss value of the issue jwt.
   * It is also used as the client_id.
   * And will also be set as the redirect_uri
   *
   * It must match an entry in the x5c certificate leaf entry dnsName / uriName
   */
  issuer: string

  clientIdScheme: 'x509_san_dns' | 'x509_san_uri'
}

interface JwtIssuerJwk extends JwtIssuerBase {
  method: 'jwk'

  jwk: JsonWebKey
}

interface JwtIssuerCustom extends JwtIssuerBase {
  method: 'custom'
}

export type JwtIssuer = JwtIssuerDid | JwtIssuerX5c | JwtIssuerJwk | JwtIssuerCustom
export type JwtIssuerWithContext = JwtIssuer & JwtIssuanceContext

export type CreateJwtCallback = (jwtIssuer: JwtIssuerWithContext, jwt: { header: JwtHeader; payload: JwtPayload }) => Promise<string>
