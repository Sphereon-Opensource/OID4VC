import { jwtDecode } from 'jwt-decode'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { fromString, toString } from 'uint8arrays'
import { v4 as uuidv4 } from 'uuid'

import { defaultHasher } from '../hasher'
import {
  calculateJwkThumbprint,
  CreateJwtCallback,
  epochTime,
  getNowSkewed,
  JWK,
  JwtHeader,
  JwtIssuerJwk,
  JwtPayload,
  parseJWT,
  SigningAlgo,
  VerifyJwtCallbackBase,
} from '../jwt'

export const dpopTokenRequestNonceError = 'use_dpop_nonce'

export interface DPoPJwtIssuerWithContext extends JwtIssuerJwk {
  type: 'dpop'
  dPoPSigningAlgValuesSupported?: string[]
}

export type DPoPJwtPayloadProps = {
  htu: string
  iat: number
  htm: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'OPTIONS' | 'TRACE' | 'CONNECT' | 'PATCH'
  ath?: string
  nonce?: string
  jti: string
}
export type DPoPJwtHeaderProps = { typ: 'dpop+jwt'; alg: SigningAlgo; jwk: JWK }
export type CreateDPoPJwtPayloadProps = Omit<DPoPJwtPayloadProps, 'iat' | 'jti' | 'ath'> & { accessToken?: string }

export interface CreateDPoPOpts<JwtPayloadProps = CreateDPoPJwtPayloadProps> {
  createJwtCallback: CreateJwtCallback<DPoPJwtIssuerWithContext>
  jwtIssuer: Omit<JwtIssuerJwk, 'method' | 'type'>
  jwtPayloadProps: Record<string, unknown> & JwtPayloadProps
  dPoPSigningAlgValuesSupported?: (string | SigningAlgo)[]
}

export type CreateDPoPClientOpts = CreateDPoPOpts<Omit<CreateDPoPJwtPayloadProps, 'htm' | 'htu'>>

export function getCreateDPoPOptions(
  createDPoPClientOpts: CreateDPoPClientOpts,
  endPointUrl: string,
  resourceRequestOpts?: { accessToken: string },
): CreateDPoPOpts {
  const htu = endPointUrl.split('?')[0].split('#')[0]
  return {
    ...createDPoPClientOpts,
    jwtPayloadProps: {
      ...createDPoPClientOpts.jwtPayloadProps,
      htu,
      htm: 'POST',
      ...(resourceRequestOpts && { accessToken: resourceRequestOpts.accessToken }),
    },
  }
}

export async function createDPoP(options: CreateDPoPOpts): Promise<string> {
  const { createJwtCallback, jwtIssuer, jwtPayloadProps, dPoPSigningAlgValuesSupported } = options

  if (jwtPayloadProps.accessToken && (jwtPayloadProps.accessToken?.startsWith('DPoP ') || jwtPayloadProps.accessToken?.startsWith('Bearer '))) {
    throw new Error('expected access token without scheme')
  }

  const ath = jwtPayloadProps.accessToken ? toString(defaultHasher(jwtPayloadProps.accessToken, 'sha256'), 'base64url') : undefined
  return createJwtCallback(
    { method: 'jwk', type: 'dpop', alg: jwtIssuer.alg, jwk: jwtIssuer.jwk, dPoPSigningAlgValuesSupported },
    {
      header: { ...jwtIssuer, typ: 'dpop+jwt', alg: jwtIssuer.alg, jwk: jwtIssuer.jwk },
      payload: {
        ...jwtPayloadProps,
        iat: epochTime(),
        jti: uuidv4(),
        ...(ath && { ath }),
      },
    },
  )
}

export type DPoPVerifyJwtCallback = VerifyJwtCallbackBase<JwtIssuerJwk & { type: 'dpop' }>
export interface DPoPVerifyOptions {
  expectedNonce?: string
  acceptedAlgorithms?: (string | SigningAlgo)[]
  // defaults to 300 seconds (5 minutes)
  maxIatAgeInSeconds?: number
  expectAccessToken?: boolean
  jwtVerifyCallback: DPoPVerifyJwtCallback
  now?: number
}

export async function verifyDPoP(
  request: { headers: Record<string, string | string[] | undefined>; fullUrl: string } & Pick<Request, 'method'>,
  options: DPoPVerifyOptions,
) {
  // There is not more than one DPoP HTTP request header field.
  const dpop = request.headers['dpop']
  if (!dpop || typeof dpop !== 'string') {
    throw new Error('missing or invalid dpop header. Expected compact JWT')
  }

  // The DPoP HTTP request header field value is a single and well-formed JWT.
  const { header: dPoPHeader, payload: dPoPPayload } = parseJWT<JwtHeader, JwtPayload & Partial<DPoPJwtPayloadProps>>(dpop)

  // Ensure all required header claims are present
  if (dPoPHeader.typ !== 'dpop+jwt' || !dPoPHeader.alg || !dPoPHeader.jwk || typeof dPoPHeader.jwk !== 'object' || dPoPHeader.jwk.d) {
    throw new Error('invalid_dpop_proof. Invalid header claims')
  }

  // Ensure all required payload claims are present
  if (!dPoPPayload.htm || !dPoPPayload.htu || !dPoPPayload.iat || !dPoPPayload.jti) {
    throw new Error('invalid_dpop_proof. Missing required claims')
  }

  // Validate alg is supported
  if (options?.acceptedAlgorithms && !options.acceptedAlgorithms.includes(dPoPHeader.alg)) {
    throw new Error(`invalid_dpop_proof. Invalid 'alg' claim '${dPoPHeader.alg}'. Only ${options.acceptedAlgorithms.join(', ')} are supported.`)
  }

  // Validate nonce if provided
  if ((options?.expectedNonce && !dPoPPayload.nonce) || dPoPPayload.nonce !== options.expectedNonce) {
    throw new Error('invalid_dpop_proof. Nonce mismatch')
  }

  // Verify JWT signature
  try {
    const verificationResult = await options.jwtVerifyCallback(
      {
        method: 'jwk',
        type: 'dpop',
        jwk: dPoPHeader.jwk,
        alg: dPoPHeader.alg,
      },
      {
        header: dPoPHeader,
        payload: dPoPPayload,
        raw: dpop,
      },
    )

    if (!verificationResult) {
      throw new Error('invalid_dpop_proof. Invalid JWT signature')
    }
  } catch (error: unknown) {
    throw new Error('invalid_dpop_proof. Invalid JWT signature. ' + (error instanceof Error ? error.message : 'Unknown error'))
  }

  // Validate htm claim
  if (dPoPPayload.htm !== request.method) {
    throw new Error(`invalid_dpop_proof. Invalid htm claim. Must match request method '${request.method}'`)
  }

  // The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment parts.
  const currentUri = request.fullUrl.split('?')[0].split('#')[0]
  if (dPoPPayload.htu !== currentUri) {
    throw new Error('invalid_dpop_proof. Invalid htu claim')
  }

  // Validate nonce if provided
  if ((options.expectedNonce && dPoPPayload.nonce !== options.expectedNonce) || (!options.expectedNonce && dPoPPayload.nonce)) {
    throw new Error('invalid_dpop_proof. Nonce mismatch')
  }

  // Validate iat claim
  const { nowSkewedPast, nowSkewedFuture } = getNowSkewed(options.now)
  if (
    // iat claim is too far in the future
    nowSkewedPast - (options.maxIatAgeInSeconds ?? 60) > dPoPPayload.iat ||
    // iat claim is too old
    nowSkewedFuture + (options.maxIatAgeInSeconds ?? 60) < dPoPPayload.iat
  ) {
    // 5 minute window
    throw new Error('invalid_dpop_proof. Invalid iat claim')
  }

  // If access token is present, validate ath claim
  const authorizationHeader = request.headers.authorization
  if (!options.expectAccessToken && authorizationHeader) {
    throw new Error('invalid_dpop_proof. Received an unexpected authorization header.')
  }

  if (options.expectAccessToken) {
    if (!dPoPPayload.ath) {
      throw new Error('invalid_dpop_proof. Missing expected ath claim.')
    }

    // validate that the DPOP proof is made for the provided access token
    if (!authorizationHeader || typeof authorizationHeader !== 'string' || !authorizationHeader.startsWith('DPoP ')) {
      throw new Error('invalid_dpop_proof. Invalid authorization header.')
    }

    const accessToken = authorizationHeader.replace('DPoP ', '')
    const expectedAth = toString(defaultHasher(accessToken, 'sha256'), 'base64url')
    if (dPoPPayload.ath !== expectedAth) {
      throw new Error('invalid_dpop_proof. Invalid ath claim')
    }

    // validate that the access token is signed with the same key as the DPOP proof
    const accessTokenPayload = jwtDecode<JwtPayload & { cnf?: { jkt?: string } }>(accessToken, { header: false })
    if (!accessTokenPayload.cnf?.jkt) {
      throw new Error('invalid_dpop_proof. Access token is missing the jkt claim')
    }

    const thumprint = await calculateJwkThumbprint(dPoPHeader.jwk, 'sha256')
    if (accessTokenPayload.cnf?.jkt !== thumprint) {
      throw new Error('invalid_dpop_proof. JwkThumbprint mismatch')
    }
  }

  // If all validations pass, return the dpop jwk
  return dPoPHeader.jwk
}

/**
 * DPoP verifications for resource requests
 * For Bearer token compatibility jwt's must have a token_type claim
 * The access token itself must be validated before using this method
 * If the token_type is not DPoP, then the request is not a DPoP request
 * and we don't need to verify the DPoP proof
 */
export async function verifyResourceDPoP(
  request: { headers: Record<string, string | string[] | undefined>; fullUrl: string } & Pick<Request, 'method'>,
  options: Omit<DPoPVerifyOptions, 'expectAccessToken'>,
) {
  if (!request.headers.authorization || typeof request.headers.authorization !== 'string') {
    throw new Error('Received an invalid resource request. Missing authorization header.')
  }
  const tokenPayload = jwtDecode<JwtPayload & { token_type?: string }>(request.headers.authorization, { header: false })
  const tokenType = tokenPayload.token_type

  if (tokenType !== 'DPoP') {
    return
  }

  return verifyDPoP(request, { ...options, expectAccessToken: true })
}
