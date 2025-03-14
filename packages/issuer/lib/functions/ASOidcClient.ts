import { decodeJwt, decodeProtectedHeader } from '@sphereon/oid4vc-common'
import { ClientMetadata, JWTHeader, JWTVerifyCallback, JwtVerifyResult } from '@sphereon/oid4vci-common'
import { oidcDiscoverIssuer, oidcGetClient } from '@sphereon/ssi-express-support'

export function oidcAccessTokenVerifyCallback(opts: {
  credentialIssuer: string
  authorizationServer: string
  clientMetadata?: ClientMetadata
}): JWTVerifyCallback {
  const clientMetadata = opts.clientMetadata ?? { client_id: opts.credentialIssuer }

  return async (args: { jwt: string; kid?: string }): Promise<JwtVerifyResult> => {
    const oidcIssuer = await oidcDiscoverIssuer({ issuerUrl: opts.authorizationServer })
    const oidcClient = await oidcGetClient(oidcIssuer.issuer, clientMetadata)
    const introspection = await oidcClient.introspect(args.jwt)
    if (!introspection.active) {
      return Promise.reject(Error('Access token is not active or invalid'))
    }
    const jwt = { header: decodeProtectedHeader(args.jwt) as JWTHeader, payload: decodeJwt(args.jwt) }

    return {
      jwt,
      alg: jwt.header.alg,
      ...(jwt.header.jwk && { jwk: jwt.header.jwk }),
      ...(jwt.header.x5c && { x5c: jwt.header.x5c }),
      ...(jwt.header.kid && { kid: jwt.header.kid }),
      // We could resolve the did document here if the kid is a VM
    }
  }
}
