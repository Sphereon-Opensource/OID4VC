import { Loggers, ObjectUtils } from '@sphereon/ssi-types'
import { jwtDecode, JwtPayload } from 'jwt-decode'
import { CredentialOfferPayloadV1_0_15, VCI_LOG_COMMON } from '../index'

import {
  AssertedUniformCredentialOffer,
  AuthzFlowType,
  CredentialOffer,
  CredentialOfferPayload,
  DefaultURISchemes,
  Grant,
  GrantTypes,
  OpenId4VCIVersion,
  OpenIDResponse,
  PRE_AUTH_CODE_LITERAL,
  PRE_AUTH_GRANT_LITERAL,
  UniformCredentialOffer,
  UniformCredentialOfferPayload,
  UniformCredentialOfferRequest,
} from '../types'

import { getJson } from './HttpUtils'
import { base64urlToString } from '@sphereon/oid4vc-common'

const logger = Loggers.DEFAULT.get('sphereon:oid4vci:offer')

export function determineSpecVersionFromURI(uri: string): OpenId4VCIVersion {
  let version = determineSpecVersionFromScheme(uri, OpenId4VCIVersion.VER_UNKNOWN) ?? OpenId4VCIVersion.VER_UNKNOWN
  // version = getVersionFromURIParam(uri, version, [OpenId4VCIVersion.VER_1_0_13, OpenId4VCIVersion.VER_1_0_15], 'tx_code')  (left as examples)
  // version = getVersionFromURIParam(uri, version, [OpenId4VCIVersion.VER_1_0_15], 'credential_offer_uri ') // optional so last resort
  if (version === OpenId4VCIVersion.VER_UNKNOWN) {
    version = OpenId4VCIVersion.VER_1_0_15
  }
  return version
}

export function determineSpecVersionFromScheme(credentialOfferURI: string, openId4VCIVersion: OpenId4VCIVersion) {
  const scheme = getScheme(credentialOfferURI)

  const url = toUrlWithDummyBase(credentialOfferURI)
  const qp = url.searchParams

  // ----------------- 1) openid-initiate-issuance -----------------
  if (scheme === DefaultURISchemes.INITIATE_ISSUANCE) {
    // v15 indicators
    if (qp.has('credential_offer') || qp.has('credential_offer_uri')) {
      return recordVersion(openId4VCIVersion, [OpenId4VCIVersion.VER_1_0_15], scheme)
    }

    // Could not decide
    return recordVersion(openId4VCIVersion, [OpenId4VCIVersion.VER_UNKNOWN], scheme)
  }

  // ----------------- 2) openid-credential-offer -----------------
  if (scheme === DefaultURISchemes.CREDENTIAL_OFFER) {
    // Indirection URI -> Draft 15 style (can't confirm 11/13 via scheme alone)
    if (qp.has('credential_offer_uri')) {
      return recordVersion(openId4VCIVersion, [OpenId4VCIVersion.VER_1_0_15], scheme)
    }

    // Inline payload -> sniff JSON keys
    const rawParam = getParamValueLoose(qp, 'credential_offer')
    if (rawParam) {
      const decoded = tryDecodeOffer(rawParam)

      const version = sniffOfferVersion(decoded)
      if (version !== OpenId4VCIVersion.VER_UNKNOWN) {
        return recordVersion(openId4VCIVersion, [version], scheme)
      }
    }

    // If we still can't tell, DO NOT default to 15 — stay unknown
    return recordVersion(openId4VCIVersion, [OpenId4VCIVersion.VER_UNKNOWN], scheme)
  }

  // ----------------- 3) Unknown scheme -----------------
  return recordVersion(openId4VCIVersion, [OpenId4VCIVersion.VER_UNKNOWN], scheme)
}

/* ----------------- helpers ----------------- */

/**
 * Replace custom "openid-..." schemes with a dummy base so URL() can parse query params.
 * Make sure to end with '/?' to avoid the "?param" name issue.
 */
function toUrlWithDummyBase(uri: string): URL {
  const normalized = uri.replace(/^openid-[^?]+:\/\//, 'https://dummy/?')
  return new URL(normalized)
}

/**
 * Some runtimes/libraries have bugs that result in the param name being `'?credential_offer'`.
 * This helper checks both.
 */
function getParamValueLoose(qp: URLSearchParams, key: string): string | null {
  if (qp.has(key)) return qp.get(key)
  if (qp.has(`?${key}`)) return qp.get(`?${key}`)
  return null
}

/**
 * Try to decode the inline offer string:
 *  1) decodeURIComponent if needed,
 *  2) base64url decode if it looks base64y,
 * return the final string (JSON) or empty string on failure.
 */
function tryDecodeOffer(input: string): string {
  let candidate = input

  try {
    candidate = decodeURIComponent(candidate)
  } catch {
    /* ignore */
  }
  // Fast check for base64url: only URL-safe chars and no braces
  if (!/[{}]/.test(candidate) && /^[A-Za-z0-9\-_]+$/.test(candidate)) {
    try {
      const b64 = candidate
        .replace(/-/g, '+')
        .replace(/_/g, '/')
        .padEnd(Math.ceil(candidate.length / 4) * 4, '=')
      candidate = atob(b64)
    } catch {
      /* ignore */
    }
  }
  return candidate // may still be encoded JSON but good enough for key sniffing
}

/**
 * Look for version-specific keys.
 * returns only  VER_UNKNOWN atm, for future versions support
 */
function sniffOfferVersion(jsonLike: string): OpenId4VCIVersion {
  if (!jsonLike) return OpenId4VCIVersion.VER_UNKNOWN

  // Use cheap regex so we don't crash on invalid JSON
  // const has = (k: string) => new RegExp(`"${k}"\\s*:`, 'i').test(jsonLike);
  // if (has('credentials')) return OpenId4VCIVersion.VER_1_0_11;  left as example

  return OpenId4VCIVersion.VER_UNKNOWN
}

export function getScheme(credentialOfferURI: string) {
  if (!credentialOfferURI || !credentialOfferURI.includes('://')) {
    throw Error('Invalid credential offer URI')
  }
  return credentialOfferURI.split('://')[0]
}

export function getIssuerFromCredentialOfferPayload(request: CredentialOfferPayload): string | undefined {
  if (!request || (!('issuer' in request) && !('credential_issuer' in request))) {
    return undefined
  }
  return 'issuer' in request ? request.issuer : request['credential_issuer']
}

export const getClientIdFromCredentialOfferPayload = (credentialOffer?: CredentialOfferPayload): string | undefined => {
  if (!credentialOffer) {
    return
  }
  if ('client_id' in credentialOffer) {
    return credentialOffer.client_id
  }

  const state: string | undefined = getStateFromCredentialOfferPayload(credentialOffer)
  if (state && isJWT(state)) {
    const decoded = jwtDecode<JwtPayload>(state, { header: false })
    if ('client_id' in decoded && typeof decoded.client_id === 'string') {
      return decoded.client_id
    }
  }
  return
}

const isJWT = (input?: string) => {
  if (!input) {
    return false
  }
  const noParts = input?.split('.').length
  return input?.startsWith('ey') && noParts === 3
}
export const getStateFromCredentialOfferPayload = (credentialOffer: CredentialOfferPayload): string | undefined => {
  if ('grants' in credentialOffer) {
    if (credentialOffer.grants?.authorization_code) {
      return credentialOffer.grants.authorization_code.issuer_state
    } else if (credentialOffer.grants?.[PRE_AUTH_GRANT_LITERAL]) {
      return credentialOffer.grants?.[PRE_AUTH_GRANT_LITERAL]?.[PRE_AUTH_CODE_LITERAL]
    }
  }
  if ('op_state' in credentialOffer) {
    // older spec versions
    return credentialOffer.op_state
  } else if (PRE_AUTH_CODE_LITERAL in credentialOffer) {
    return credentialOffer[PRE_AUTH_CODE_LITERAL]
  }

  return
}

export function determineSpecVersionFromOffer(offer: CredentialOfferPayload | CredentialOffer): OpenId4VCIVersion {
  if (isCredentialOfferV1_0_15(offer)) {
    // Cannot distinguish 1.0 final from draft 15 based on offer alone (same fields).
    // Default to VER_1_0_15 from offer. The wallet will upgrade after fetching metadata.
    return OpenId4VCIVersion.VER_1_0_15
  }
  return OpenId4VCIVersion.VER_UNKNOWN
}

export function isCredentialOfferVersion(offer: CredentialOfferPayload | CredentialOffer, min: OpenId4VCIVersion, max?: OpenId4VCIVersion) {
  if (max && max.valueOf() < min.valueOf()) {
    throw Error(`Cannot have a max ${max.valueOf()} version smaller than the min version ${min.valueOf()}`)
  }
  const version = determineSpecVersionFromOffer(offer)
  if (version.valueOf() < min.valueOf()) {
    logger.debug(`Credential offer version (${version.valueOf()}) is lower than minimum required version (${min.valueOf()})`)
    return false
  } else if (max && version.valueOf() > max.valueOf()) {
    logger.debug(`Credential offer version (${version.valueOf()}) is higher than maximum required version (${max.valueOf()})`)
    return false
  }
  return true
}

function isCredentialOfferV1_0_15(offer: CredentialOfferPayload | CredentialOffer): boolean {
  if (!offer) {
    return false
  }
  offer = normalizeOfferInput(offer)

  // Direct payload
  if ('credential_issuer' in offer && 'credential_configuration_ids' in offer) {
    return Array.isArray((offer as any).credential_configuration_ids)
  }

  // Wrapped in credential_offer
  if ('credential_offer' in offer && offer['credential_offer']) {
    return isCredentialOfferV1_0_15((offer as any)['credential_offer'])
  }

  // Fallback: URI only (credential_offer_uri) – still v15 style but cannot assert without dereferencing.
  return 'credential_offer_uri' in offer
}

export async function toUniformCredentialOfferRequest(
  offer: CredentialOffer,
  opts?: {
    resolve?: boolean
    version?: OpenId4VCIVersion
  },
): Promise<UniformCredentialOfferRequest> {
  let version = opts?.version ?? determineSpecVersionFromOffer(offer)
  let originalCredentialOffer = offer.credential_offer
  let credentialOfferURI: string | undefined
  if ('credential_offer_uri' in offer && offer?.credential_offer_uri !== undefined) {
    credentialOfferURI = offer.credential_offer_uri

    if (opts?.resolve || opts?.resolve === undefined) {
      VCI_LOG_COMMON.log(`Credential offer contained a URI. Will use that to get the credential offer payload: ${credentialOfferURI}`)
      originalCredentialOffer = (await resolveCredentialOfferURI(credentialOfferURI)) as CredentialOfferPayloadV1_0_15
    } else if (!originalCredentialOffer) {
      throw Error(`Credential offer uri (${credentialOfferURI}) found, but resolution was explicitly disabled and credential_offer was supplied`)
    }
    // We need to redetermine the version of the offer, as we only had the offer_uri until now
    version = determineSpecVersionFromOffer(originalCredentialOffer)
    VCI_LOG_COMMON.log(`Offer URI payload determined to be of version ${version}`)
  }
  if (!originalCredentialOffer) {
    throw Error('No credential offer available')
  }
  const payload = toUniformCredentialOfferPayload(originalCredentialOffer, { ...opts, version })
  const supportedFlows = determineFlowType(payload, version)
  return {
    credential_offer: payload,
    original_credential_offer: originalCredentialOffer,
    ...(credentialOfferURI && { credential_offer_uri: credentialOfferURI }),
    supportedFlows,
    version,
  }
}

export function isPreAuthCode(request: UniformCredentialOfferPayload | UniformCredentialOffer) {
  request = normalizeOfferInput(request)

  const payload = 'credential_offer' in request ? request.credential_offer : (request as UniformCredentialOfferPayload)
  return payload?.grants?.[PRE_AUTH_GRANT_LITERAL]?.[PRE_AUTH_CODE_LITERAL] !== undefined
}

export async function assertedUniformCredentialOffer(
  origCredentialOffer: UniformCredentialOffer,
  opts?: {
    resolve?: boolean
  },
): Promise<AssertedUniformCredentialOffer> {
  const credentialOffer = JSON.parse(JSON.stringify(origCredentialOffer))
  if (credentialOffer.credential_offer_uri && !credentialOffer.credential_offer) {
    if (opts?.resolve === undefined || opts.resolve) {
      credentialOffer.credential_offer = await resolveCredentialOfferURI(credentialOffer.credential_offer_uri)
    } else {
      throw Error(`No credential_offer present, but we did get a URI, but resolution was explicitly disabled`)
    }
  }
  if (!credentialOffer.credential_offer) {
    throw Error(`No credential_offer present`)
  }
  credentialOffer.credential_offer = await toUniformCredentialOfferPayload(credentialOffer.credential_offer, { version: credentialOffer.version })
  return credentialOffer as AssertedUniformCredentialOffer
}

export async function resolveCredentialOfferURI(uri?: string): Promise<UniformCredentialOfferPayload | undefined> {
  if (!uri) {
    return undefined
  }
  const response = (await getJson(uri)) as OpenIDResponse<UniformCredentialOfferPayload>
  if (!response || !response.successBody) {
    throw Error(`Could not get credential offer from uri: ${uri}: ${JSON.stringify(response?.errorBody)}`)
  }
  return response.successBody as UniformCredentialOfferPayload
}

export function toUniformCredentialOfferPayload(
  rawOffer: CredentialOfferPayload,
  opts?: {
    version?: OpenId4VCIVersion
  },
): UniformCredentialOfferPayload {
  const offer = normalizeOfferInput<CredentialOfferPayload>(rawOffer)

  // todo: create test to check idempotence once a payload is already been made uniform.
  const version = opts?.version ?? determineSpecVersionFromOffer(offer)
  if (version >= OpenId4VCIVersion.VER_1_0_15) {
    const orig = offer as UniformCredentialOfferPayload
    return {
      ...orig,
    }
  }

  throw Error(`Could not create uniform payload for version ${version}`)
}

export function determineFlowType(
  suppliedOffer: AssertedUniformCredentialOffer | UniformCredentialOfferPayload,
  version: OpenId4VCIVersion,
): AuthzFlowType[] {
  const payload: UniformCredentialOfferPayload = getCredentialOfferPayload(suppliedOffer)
  const supportedFlows: AuthzFlowType[] = []
  if (payload.grants?.authorization_code) {
    supportedFlows.push(AuthzFlowType.AUTHORIZATION_CODE_FLOW)
  }
  if (payload.grants?.[PRE_AUTH_GRANT_LITERAL]?.[PRE_AUTH_CODE_LITERAL]) {
    supportedFlows.push(AuthzFlowType.PRE_AUTHORIZED_CODE_FLOW)
  }
  return supportedFlows
}

export function getCredentialOfferPayload(offer: AssertedUniformCredentialOffer | UniformCredentialOfferPayload): UniformCredentialOfferPayload {
  offer = normalizeOfferInput(offer)

  let payload: UniformCredentialOfferPayload
  if ('credential_offer' in offer && offer['credential_offer']) {
    payload = offer.credential_offer
  } else {
    payload = offer as UniformCredentialOfferPayload
  }
  return payload
}

export function determineGrantTypes(
  offer:
    | AssertedUniformCredentialOffer
    | UniformCredentialOfferPayload
    | ({
        grants: Grant
      } & Record<never, never>),
): GrantTypes[] {
  offer = normalizeOfferInput(offer)

  let grants: Grant | undefined
  if ('grants' in offer && offer.grants) {
    grants = offer.grants
  } else {
    grants = getCredentialOfferPayload(offer as AssertedUniformCredentialOffer | UniformCredentialOfferPayload).grants
  }

  const types: GrantTypes[] = []
  if (grants) {
    if ('authorization_code' in grants) {
      types.push(GrantTypes.AUTHORIZATION_CODE)
    }
    if (PRE_AUTH_GRANT_LITERAL in grants) {
      types.push(GrantTypes.PRE_AUTHORIZED_CODE)
    }
  }
  return types
}
/*
function getVersionFromURIParam(
  credentialOfferURI: string,
  currentVersion: OpenId4VCIVersion,
  matchingVersion: OpenId4VCIVersion[],
  param: string,
  allowUpgrade = true
) {
  if (credentialOfferURI.includes(param)) {
    return recordVersion(currentVersion, matchingVersion, param, allowUpgrade)
  }
  return currentVersion
}*/

function recordVersion(currentVersion: OpenId4VCIVersion, matchingVersion: OpenId4VCIVersion[], key: string, allowUpgrade = true) {
  matchingVersion = matchingVersion.sort().reverse()
  if (currentVersion === OpenId4VCIVersion.VER_UNKNOWN) {
    return matchingVersion[0]
  } else if (matchingVersion.includes(currentVersion)) {
    if (!allowUpgrade) {
      return currentVersion
    }
    return matchingVersion[0]
  }

  throw new Error(
    `Invalid param. Some keys have been used from version: ${currentVersion} version while '${key}' is used from version: ${JSON.stringify(matchingVersion)}`,
  )
}

export function getCredentialConfigurationIdsFromOfferV1_0_15(offer: CredentialOfferPayloadV1_0_15): string[] {
  return offer.credential_configuration_ids ?? []
}

export function normalizeOfferInput<T = any>(input: unknown): T {
  if (typeof input !== 'string') {
    return input as T
  }

  // JWT?
  if (ObjectUtils.isString(input) && input.startsWith('ey')) {
    const payload = base64urlToString(input)
    return JSON.parse(payload) as T
  }

  // JSON?
  try {
    return JSON.parse(input) as T
  } catch {}

  // Last resort: just return as-is
  return input as T
}
