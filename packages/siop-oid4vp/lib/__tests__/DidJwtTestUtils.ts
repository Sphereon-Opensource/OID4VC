import { JwtPayload, parseJWT, SigningAlgo } from '@sphereon/oid4vci-common'
import { VerifyCallback } from '@sphereon/wellknown-dids-client'
import { createJWT, EdDSASigner, ES256KSigner, ES256Signer, hexToBytes, JWTOptions, JWTVerifyOptions, Signer, verifyJWT } from 'did-jwt'
import { Resolvable } from 'did-resolver'

import { DEFAULT_EXPIRATION_TIME, ResponseIss, SIOPErrors, VerifiedJWT, VerifyJwtCallback } from '../types'

import { getResolver } from './ResolverTestUtils'

export async function verifyDidJWT(jwt: string, resolver: Resolvable, options: JWTVerifyOptions): Promise<VerifiedJWT> {
  return verifyJWT(jwt, { ...options, resolver })
}

/**
 *  Creates a signed JWT given an address which becomes the issuer, a signer function, and a payload for which the withSignature is over.
 *
 *  @example
 *  const signer = ES256KSigner(process.env.PRIVATE_KEY)
 *  createJWT({address: '5A8bRWU3F7j3REx3vkJ...', signer}, {key1: 'value', key2: ..., ... }).then(JWT => {
 *      ...
 *  })
 *
 *  @param    {Object}            payload               payload object
 *  @param    {Object}            [options]             an unsigned credential object
 *  @param    {String}            options.issuer        The DID of the issuer (signer) of JWT
 *  @param    {Signer}            options.signer        a `Signer` function, Please see `ES256KSigner` or `EdDSASigner`
 *  @param    {boolean}           options.canonicalize  optional flag to canonicalize header and payload before signing
 *  @param    {Object}            header                optional object to specify or customize the JWT header
 *  @return   {Promise<Object, Error>}                  a promise which resolves with a signed JSON Web Token or rejects with an error
 */
export async function createDidJWT(
  payload: Partial<JwtPayload>,
  { issuer, signer, expiresIn, canonicalize }: JWTOptions,
  header: Partial<JwtPayload>,
): Promise<string> {
  return createJWT(payload, { issuer, signer, expiresIn, canonicalize }, header)
}
export interface InternalSignature {
  hexPrivateKey: string // hex private key Only secp256k1 format
  did: string

  alg: SigningAlgo
  kid?: string // Optional: key identifier

  customJwtSigner?: Signer
}

export function getAudience(jwt: string) {
  const { payload } = parseJWT(jwt)
  if (!payload) {
    throw new Error(SIOPErrors.NO_AUDIENCE)
  } else if (!payload.aud) {
    return undefined
  } else if (Array.isArray(payload.aud)) {
    throw new Error(SIOPErrors.INVALID_AUDIENCE)
  }

  return payload.aud
}

export const internalSignature = (hexPrivateKey: string, did: string, didUrl: string, alg: SigningAlgo) => {
  return getCreateJwtCallback({
    hexPrivateKey,
    kid: didUrl,
    alg,
    did,
  })
}

export function getCreateJwtCallback(signature: InternalSignature) {
  return (jwtIssuer, jwt) => {
    if (jwtIssuer.method === 'did') {
      const issuer = jwtIssuer.didUrl.split('#')[0]
      if (!signature.kid) throw new Error('Missing kid')
      return signDidJwtInternal(jwt.payload, issuer, signature.hexPrivateKey, signature.alg, signature.kid, signature.customJwtSigner)
    } else if (jwtIssuer.method === 'custom') {
      if (jwtIssuer.type === 'request-object') {
        const did = signature.did
        jwt.payload.iss = jwt.payload.iss ?? did
        jwt.payload.sub = jwt.payload.sub ?? did
        jwt.payload.client_id = jwt.payload.client_id ?? did
      }

      if (!signature.kid) throw new Error('Missing kid')
      if (jwtIssuer.type === 'id-token') {
        if (!jwt.payload.sub) jwt.payload.sub = signature.did

        const issuer = jwtIssuer.authorizationResponseOpts.registration?.issuer || this._payload.iss
        if (!issuer || !(issuer.includes(ResponseIss.SELF_ISSUED_V2) || issuer === this._payload.sub)) {
          throw new Error(SIOPErrors.NO_SELF_ISSUED_ISS)
        }
        if (!jwt.payload.iss) {
          jwt.payload.iss = issuer
        }
        return signDidJwtInternal(jwt.payload, issuer, signature.hexPrivateKey, signature.alg, signature.kid, signature.customJwtSigner)
      }

      return signDidJwtInternal(jwt.payload, signature.did, signature.hexPrivateKey, signature.alg, signature.kid, signature.customJwtSigner)
    }
    throw new Error('Not implemented yet')
  }
}

export function getVerifyJwtCallback(
  resolver?: Resolvable,
  verifyOpts?: JWTVerifyOptions & {
    checkLinkedDomain: 'never' | 'if_present' | 'always'
    wellknownDIDVerifyCallback?: VerifyCallback
  },
): VerifyJwtCallback {
  return async (jwtVerifier, jwt) => {
    resolver = resolver ?? getResolver(['ethr', 'ion'])
    const audience =
      jwtVerifier.type === 'request-object'
        ? (verifyOpts?.audience ?? getAudience(jwt.raw))
        : jwtVerifier.type === 'id-token'
          ? (verifyOpts?.audience ?? getAudience(jwt.raw))
          : undefined

    await verifyDidJWT(jwt.raw, resolver, { audience, ...verifyOpts })
    // we can always because the verifyDidJWT will throw an error if the JWT is invalid
    return true
  }
}

async function signDidJwtInternal(
  payload: JwtPayload,
  issuer: string,
  hexPrivateKey: string,
  alg: SigningAlgo,
  kid: string,
  customJwtSigner?: Signer,
): Promise<string> {
  const signer = determineSigner(alg, hexPrivateKey, customJwtSigner)
  const header = {
    alg,
    kid,
  }
  const options = {
    issuer,
    signer,
    expiresIn: DEFAULT_EXPIRATION_TIME,
  }

  return await createDidJWT({ ...payload }, options, header)
}

const determineSigner = (alg: SigningAlgo, hexPrivateKey?: string, customSigner?: Signer): Signer => {
  if (customSigner) {
    return customSigner
  } else if (!hexPrivateKey) {
    throw new Error('no private key provided')
  }
  const privateKey = hexToBytes(hexPrivateKey.replace('0x', ''))
  switch (alg) {
    case SigningAlgo.EDDSA:
      return EdDSASigner(privateKey)
    case SigningAlgo.ES256:
      return ES256Signer(privateKey)
    case SigningAlgo.ES256K:
      return ES256KSigner(privateKey)
    case SigningAlgo.PS256:
      throw Error('PS256 is not supported yet. Please provide a custom signer')
    case SigningAlgo.RS256:
      throw Error('RS256 is not supported yet. Please provide a custom signer')
  }
}
