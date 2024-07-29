import { AuthorizationRequestPayload, IDTokenPayload, JwtIssuerWithContext, RequestObjectPayload } from '@sphereon/did-auth-siop'
import { JwtVerifier } from '@sphereon/did-auth-siop'
import { JwtHeader, JwtPayload } from '@sphereon/common'
import { Resolvable } from 'did-resolver'

import { getAudience, getSubDidFromPayload, signIDTokenPayload, signRequestObjectPayload, validateLinkedDomainWithDid, verifyDidJWT } from './did'
import { CheckLinkedDomain, ExternalSignature, ExternalVerification, InternalSignature, InternalVerification, SuppliedSignature } from './types'

export const verfiyDidJwtAdapter = async (
  jwtVerifier: JwtVerifier,
  jwt: { header: JwtHeader; payload: JwtPayload; raw: string },
  options: {
    verification: InternalVerification | ExternalVerification
    resolver: Resolvable
  },
): Promise<boolean> => {
  if (jwtVerifier.method === 'did') {
    const audience = options?.verification?.resolveOpts?.jwtVerifyOpts?.audience ?? getAudience(jwt.raw)

    await verifyDidJWT(jwt.raw, options.resolver, { ...options.verification?.resolveOpts?.jwtVerifyOpts, audience })

    if (jwtVerifier.type === 'request-object' && (jwt.payload as JwtPayload & { client_id?: string }).client_id?.startsWith('did:')) {
      const authorizationRequestPayload = jwt.payload as AuthorizationRequestPayload
      if (options.verification?.checkLinkedDomain && options.verification.checkLinkedDomain != CheckLinkedDomain.NEVER) {
        await validateLinkedDomainWithDid(authorizationRequestPayload.client_id, options.verification)
      } else if (!options.verification?.checkLinkedDomain && options.verification.wellknownDIDVerifyCallback) {
        await validateLinkedDomainWithDid(authorizationRequestPayload.client_id, options.verification)
      }
    }

    if (jwtVerifier.type === 'id-token') {
      const issuerDid = getSubDidFromPayload(jwt.payload)
      if (options.verification?.checkLinkedDomain && options.verification.checkLinkedDomain != CheckLinkedDomain.NEVER) {
        await validateLinkedDomainWithDid(issuerDid, options.verification)
      } else if (!options.verification?.checkLinkedDomain && options.verification.wellknownDIDVerifyCallback) {
        await validateLinkedDomainWithDid(issuerDid, options.verification)
      }
    }

    return true
  }

  throw new Error('Invalid use of the did-auth-siop create jwt adapter')
}

export const createDidJwtAdapter = async (
  signature: InternalSignature | ExternalSignature | SuppliedSignature,
  jwtIssuer: JwtIssuerWithContext,
  jwt: { header: JwtHeader; payload: JwtPayload },
): Promise<string> => {
  if (jwtIssuer.method === 'did') {
    const issuer = jwtIssuer.didUrl.split('#')[0]
    jwt.payload.issuer = issuer
    if (jwtIssuer.type === 'request-object') {
      return await signRequestObjectPayload(jwt.payload as RequestObjectPayload, signature)
    } else if (jwtIssuer.type === 'id-token') {
      return await signIDTokenPayload(jwt.payload as IDTokenPayload, signature)
    }
  }
  throw new Error('Invalid use of the did-auth-siop create jwt adapter')
}
