import {
  calculateJwkThumbprintUri,
  CustomJwtVerifier,
  DidJwtVerifier,
  getDidJwtVerifier,
  getDigestAlgorithmFromJwkThumbprintUri,
  getX5cVerifier,
  JWK,
  JwkJwtVerifier as JwkJwtVerifierBase,
  JwtHeader,
  JwtPayload,
  OpenIdFederationJwtVerifier,
  VerifyJwtCallbackBase,
  X5cJwtVerifier,
} from '@sphereon/oid4vc-common'
import { getJwtVerifierWithContext as getJwtVerifierWithContextCommon } from '@sphereon/oid4vc-common'
import { JwtType, parseJWT } from '@sphereon/oid4vc-common'

import SIOPErrors from './Errors'
import { RequestObjectPayload } from './SIOP.types'

type JwkJwtVerifier =
  | (JwkJwtVerifierBase & {
      type: 'id-token'
      jwkThumbprint: string
    })
  | (JwkJwtVerifierBase & {
      type: 'request-object' | 'verifier-attestation' | 'dpop'
      jwkThumbprint?: never
    })

export type JwtVerifier = DidJwtVerifier | X5cJwtVerifier | CustomJwtVerifier | JwkJwtVerifier | OpenIdFederationJwtVerifier

export const getJwkVerifier = async (
  jwt: { header: JwtHeader; payload: JwtPayload },
  jwkJwtVerifier: JwkJwtVerifierBase,
): Promise<JwkJwtVerifier> => {
  if (jwkJwtVerifier.type !== 'id-token') {
    // TODO: check why ts is complaining if we return the jwkJwtVerifier directly
    return {
      ...jwkJwtVerifier,
      type: jwkJwtVerifier.type,
    }
  }

  if (typeof jwt.payload.sub_jwk !== 'string') {
    throw new Error(`${SIOPErrors.INVALID_JWT} '${jwkJwtVerifier.type}' missing sub_jwk claim.`)
  }

  const jwkThumbPrintUri = jwt.payload.sub_jwk
  const digestAlgorithm = await getDigestAlgorithmFromJwkThumbprintUri(jwkThumbPrintUri)
  const selfComputedJwkThumbPrintUri = await calculateJwkThumbprintUri(jwt.header.jwk as JWK, digestAlgorithm)

  if (selfComputedJwkThumbPrintUri !== jwkThumbPrintUri) {
    throw new Error(`${SIOPErrors.INVALID_JWT} '${jwkJwtVerifier.type}' contains an invalid sub_jwk claim.`)
  }

  return { ...jwkJwtVerifier, type: jwkJwtVerifier.type, jwkThumbprint: jwt.payload.sub_jwk }
}

export const getJwtVerifierWithContext = async (
  jwt: { header: JwtHeader; payload: JwtPayload },
  options: { type: JwtType },
): Promise<JwtVerifier> => {
  const verifierWithContext = await getJwtVerifierWithContextCommon(jwt, options)

  if (verifierWithContext.method === 'jwk') {
    return getJwkVerifier(jwt, verifierWithContext)
  }

  return verifierWithContext
}

export const getRequestObjectJwtVerifier = async (
  jwt: { header: JwtHeader; payload: RequestObjectPayload },
  options: { raw: string },
): Promise<JwtVerifier> => {
  const type = 'request-object'

  const clientIdScheme = jwt.payload.client_id_scheme
  const clientId = jwt.payload.client_id

  if (!clientIdScheme) {
    return getJwtVerifierWithContext(jwt, { type })
  }

  if (clientIdScheme === 'did') {
    return getDidJwtVerifier(jwt, { type })
  } else if (clientIdScheme === 'pre-registered') {
    // All validations must be done manually
    // The Verifier metadata is obtained using [RFC7591] or through out-of-band mechanisms.
    return getJwtVerifierWithContext(jwt, { type })
  } else if (clientIdScheme === 'x509_san_dns' || clientIdScheme === 'x509_san_uri') {
    return getX5cVerifier(jwt, { type })
  } else if (clientIdScheme === 'redirect_uri') {
    if (jwt.payload.redirect_uri && jwt.payload.redirect_uri !== clientId) {
      throw new Error(SIOPErrors.INVALID_CLIENT_ID_MUST_MATCH_REDIRECT_URI)
    }
    if (options.raw.split('.').length > 2) {
      throw new Error(`${SIOPErrors.INVALID_JWT} '${type}' JWT must not not be signed.`)
    }
    return getJwtVerifierWithContext(jwt, { type })
  } else if (clientIdScheme === 'verifier_attestation') {
    const verifierAttestationSubtype = 'verifier-attestation+jwt'
    if (!jwt.header.jwt) {
      throw new Error(SIOPErrors.MISSING_ATTESTATION_JWT_WITH_CLIENT_ID_SCHEME_ATTESTATION)
    }
    // TODO: is this correct? not 100% sure based on the spec
    if (jwt.header.typ !== verifierAttestationSubtype) {
      throw new Error(SIOPErrors.MISSING_ATTESTATION_JWT_TYP)
    }

    const attestationJwt = jwt.header.jwt
    const { header: attestationHeader, payload: attestationPayload } = parseJWT(attestationJwt)

    if (
      attestationHeader.typ !== verifierAttestationSubtype ||
      attestationPayload.sub !== clientId ||
      !attestationPayload.iss ||
      typeof attestationPayload.iss !== 'string' ||
      !attestationPayload.exp ||
      typeof attestationPayload.exp !== 'number' ||
      typeof attestationPayload.cnf !== 'object' ||
      typeof attestationPayload.cnf['jwk'] !== 'object'
    ) {
      throw new Error(SIOPErrors.BAD_VERIFIER_ATTESTATION)
    }

    if (attestationPayload.redirect_uris) {
      if (
        !Array.isArray(attestationPayload.redirect_uris) ||
        attestationPayload.redirect_uris.some((value) => typeof value !== 'string') ||
        !jwt.payload.redirect_uri ||
        !attestationPayload.redirect_uris.includes(jwt.payload.redirect_uri)
      ) {
        throw new Error(SIOPErrors.BAD_VERIFIER_ATTESTATION_REDIRECT_URIS)
      }
    }

    const jwk = attestationPayload.cnf['jwk'] as JWK
    const alg = jwk.alg ?? attestationHeader.alg
    if (!alg) {
      throw new Error(`${SIOPErrors.INVALID_JWT} '${type}' JWT header is missing alg.`)
    }
    // The iss claim value of the Verifier Attestation JWT MUST identify a party the Wallet trusts for issuing Verifier Attestation JWTs.
    // If the Wallet cannot establish trust, it MUST refuse the request.
    return { method: 'jwk', type, jwk: attestationPayload.cnf['jwk'] as JWK, alg: jwk.alg ?? attestationHeader.alg }
  } else if (clientIdScheme === 'entity_id') {
    if (!clientId.startsWith('http')) {
      throw new Error(SIOPErrors.INVALID_REQUEST_OBJECT_ENTITY_ID_SCHEME_CLIENT_ID)
    }

    return { method: 'openid-federation', type, entityId: clientId }
  }

  throw new Error(SIOPErrors.INVALID_CLIENT_ID_SCHEME)
}

export type VerifyJwtCallback = VerifyJwtCallbackBase<JwtVerifier>
