import { post } from '@sphereon/did-auth-siop'
import {
  DEFAULT_EXPIRATION_TIME,
  IDTokenPayload,
  RequestObjectPayload,
  ResponseIss,
  SignatureResponse,
  SIOPErrors,
  SIOPResonse,
  VerifiedJWT,
} from '@sphereon/did-auth-siop'
import { SigningAlgo } from '@sphereon/oid4vc-common'
import {
  createJWT,
  decodeJWT,
  EdDSASigner,
  ES256KSigner,
  ES256Signer,
  hexToBytes,
  JWTHeader,
  JWTOptions,
  JWTPayload,
  JWTVerifyOptions,
  Signer,
  verifyJWT,
} from 'did-jwt'
import { Resolvable } from 'did-resolver'

import { isExternalSignature, isInternalSignature, isSuppliedSignature } from '../helpers'
import { ExternalSignature, InternalSignature, SuppliedSignature } from '../types'

/**
 *  Verifies given JWT. If the JWT is valid, the promise returns an object including the JWT, the payload of the JWT,
 *  and the did doc of the issuer of the JWT.
 *
 *  @example
 *  verifyDidJWT('did:key:example', resolver, {audience: '5A8bRWU3F7j3REx3vkJ...', callbackUrl: 'https://...'}).then(obj => {
 *      const did = obj.did                 // DIDres of signer
 *      const payload = obj.payload
 *      const doc = obj.doc                 // DIDres Document of signer
 *      const JWT = obj.JWT                 // JWT
 *      const signerKeyId = obj.signerKeyId // ID of key in DIDres document that signed JWT
 *      ...
 *  })
 *
 *  @param    {String}            jwt                   a JSON Web Token to verify
 *  @param    {Resolvable}        resolver
 *  @param    {JWTVerifyOptions}  [options]             Options
 *  @param    {String}            options.audience      DID of the recipient of the JWT
 *  @param    {String}            options.callbackUrl   callback url in JWT
 *  @return   {Promise<Object, Error>}                  a promise which resolves with a response object or rejects with an error
 */
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
  payload: Partial<JWTPayload>,
  { issuer, signer, expiresIn, canonicalize }: JWTOptions,
  header: Partial<JWTHeader>,
): Promise<string> {
  return createJWT(payload, { issuer, signer, expiresIn, canonicalize }, header)
}

export async function signIDTokenPayload(payload: IDTokenPayload, signature: InternalSignature | ExternalSignature | SuppliedSignature) {
  if (isInternalSignature(signature)) {
    if (!signature.kid) {
      return Promise.reject(Error('missing kid from signature'))
    }
    return signDidJwtInternal(payload, payload.issuer, signature.hexPrivateKey, signature.alg, signature.kid, signature.customJwtSigner)
  } else if (isExternalSignature(signature)) {
    return signDidJwtExternal(payload, signature.signatureUri, signature.authZToken, signature.alg, signature.kid)
  } else if (isSuppliedSignature(signature)) {
    if (!signature.kid) {
      return Promise.reject(Error('missing kid from signature'))
    }
    return signDidJwtSupplied(payload, payload.issuer, signature.signature, signature.alg, signature.kid)
  } else {
    throw new Error(
      'Signature parameters should be internal signature with hexPrivateKey, did, and an optional kid, or external signature parameters with signatureUri, did, and optionals parameters authZToken, hexPublicKey, and kid',
    )
  }
}

export async function signRequestObjectPayload(payload: RequestObjectPayload, signature: InternalSignature | ExternalSignature | SuppliedSignature) {
  let issuer = payload.iss
  if (!issuer) {
    issuer = signature.did
  }
  if (!issuer) {
    throw Error('No issuer supplied to sign the JWT')
  }
  if (!payload.iss) {
    payload.iss = issuer
  }
  if (!payload.sub) {
    payload.sub = signature.did
  }
  if (isInternalSignature(signature)) {
    if (!signature.kid) {
      return Promise.reject(Error('missing kid from signature'))
    }
    return signDidJwtInternal(payload, issuer, signature.hexPrivateKey, signature.alg, signature.kid, signature.customJwtSigner)
  } else if (isExternalSignature(signature)) {
    return signDidJwtExternal(payload, signature.signatureUri, signature.authZToken, signature.alg, signature.kid)
  } else if (isSuppliedSignature(signature)) {
    if (!signature.kid) {
      return Promise.reject(Error('missing kid from signature'))
    }
    return signDidJwtSupplied(payload, issuer, signature.signature, signature.alg, signature.kid)
  } else {
    throw new Error(
      'Signature parameters should be internal signature with hexPrivateKey, did, and an optional kid, or external signature parameters with signatureUri, did, and optionals parameters authZToken, hexPublicKey, and kid',
    )
  }
}

export async function signDidJwtInternal(
  payload: IDTokenPayload | RequestObjectPayload,
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

async function signDidJwtExternal(
  payload: IDTokenPayload | RequestObjectPayload,
  signatureUri: string,
  authZToken: string,
  alg: SigningAlgo,
  kid?: string,
): Promise<string> {
  const body = {
    issuer: payload.iss && payload.iss.includes('did:') ? payload.iss : payload.sub,
    payload,
    expiresIn: DEFAULT_EXPIRATION_TIME,
    alg,
    selfIssued: payload.iss && payload.iss.includes(ResponseIss.SELF_ISSUED_V2) ? payload.iss : undefined,
    kid,
  }

  const response: SIOPResonse<SignatureResponse> = await post(signatureUri, JSON.stringify(body), { bearerToken: authZToken })
  if (!response.successBody) {
    return Promise.reject(Error('the siop SignatureResponse does not have a successBody'))
  }
  return response.successBody.jws
}

async function signDidJwtSupplied(
  payload: IDTokenPayload | RequestObjectPayload,
  issuer: string,
  signer: Signer,
  alg: SigningAlgo,
  kid: string,
): Promise<string> {
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

export function getAudience(jwt: string) {
  const { payload } = decodeJWT(jwt)
  if (!payload) {
    throw new Error(SIOPErrors.NO_AUDIENCE)
  } else if (!payload.aud) {
    return undefined
  } else if (Array.isArray(payload.aud)) {
    throw new Error(SIOPErrors.INVALID_AUDIENCE)
  }

  return payload.aud
}

//TODO To enable automatic registration, it cannot be a did, but HTTPS URL
function assertIssSelfIssuedOrDid(payload: JWTPayload) {
  if (!payload.sub || !payload.sub.startsWith('did:') || !payload.iss || !isIssSelfIssued(payload)) {
    throw new Error('Token does not have a iss DID')
  }
}

export function getSubDidFromPayload(payload: JWTPayload, header?: JWTHeader): string | undefined {
  assertIssSelfIssuedOrDid(payload)

  if (isIssSelfIssued(payload)) {
    let did
    if (payload.sub && payload.sub.startsWith('did:')) {
      did = payload.sub
    }
    if (!did && header && header.kid && header.kid.startsWith('did:')) {
      did = header.kid.split('#')[0]
    }
    if (did) {
      return did
    }
  }
  return payload.sub
}

export function isIssSelfIssued(payload: JWTPayload): boolean {
  return (
    (payload.iss && (payload.iss.includes(ResponseIss.SELF_ISSUED_V1)) ||
    (payload.iss && payload.iss.includes(ResponseIss.SELF_ISSUED_V2)) ||
    payload.iss === payload.sub)
  )
}

export function getMethodFromDid(did: string): string {
  if (!did) {
    throw new Error(SIOPErrors.BAD_PARAMS)
  }
  const split = did.split(':')
  if (split.length == 1 && did.length > 0) {
    return did
  } else if (!did.startsWith('did:') || split.length < 2) {
    throw new Error(SIOPErrors.BAD_PARAMS)
  }

  return split[1]
}

/**
 * Since the OIDC SIOP spec incorrectly uses 'did:<method>:' and calls that a method, we have to fix it
 * @param didOrMethod
 */
export function toSIOPRegistrationDidMethod(didOrMethod: string) {
  let prefix = didOrMethod
  if (!didOrMethod.startsWith('did:')) {
    prefix = 'did:' + didOrMethod
  }
  const split = prefix.split(':')
  return `${split[0]}:${split[1]}`
}
