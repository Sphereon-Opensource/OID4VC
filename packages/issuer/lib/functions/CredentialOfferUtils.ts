import { uuidv4 } from '@sphereon/oid4vc-common'
import {
  AssertedUniformCredentialOffer,
  AuthorizationDetailsV1_0_15,
  CredentialIssuerMetadataOptsV1_0_15,
  CredentialOfferMode,
  CredentialOfferPayloadV1_0_15,
  CredentialOfferSession,
  CredentialOfferV1_0_15,
  Grant,
  GrantAuthorizationCode,
  GrantUrnIetf,
  IssuerMetadataV1_0_15,
  PIN_NOT_MATCH_ERROR,
  PRE_AUTH_GRANT_LITERAL,
  UniformCredentialOffer,
} from '@sphereon/oid4vci-common'

export interface CredentialOfferGrantInput {
  authorization_code?: Partial<GrantAuthorizationCode>
  [PRE_AUTH_GRANT_LITERAL]?: Partial<GrantUrnIetf>
  'urn:ietf:params:oauth:grant-type:pre-authorized_code'?: Partial<GrantUrnIetf> // FIXME? Getting typscript errors when only PRE_AUTH_GRANT_LITERAL is there
}

function createCredentialOfferGrants(inputGrants?: CredentialOfferGrantInput) {
  // Grants is optional
  if (!inputGrants || Object.keys(inputGrants).length === 0) {
    return undefined
  }

  const grants: Grant = {}
  if (inputGrants?.[PRE_AUTH_GRANT_LITERAL]) {
    const grant = {
      ...inputGrants[PRE_AUTH_GRANT_LITERAL],
      'pre-authorized_code': inputGrants[PRE_AUTH_GRANT_LITERAL]['pre-authorized_code'] ?? uuidv4(),
    }

    if (grant.tx_code && !grant.tx_code.length) {
      grant.tx_code.length = 4
    }

    grants[PRE_AUTH_GRANT_LITERAL] = grant
  }

  if (inputGrants?.authorization_code) {
    grants.authorization_code = {
      ...inputGrants.authorization_code,

      // TODO: it should be possible to create offer without issuer_state
      // this is added to avoid breaking changes.
      issuer_state: inputGrants.authorization_code.issuer_state ?? uuidv4(),
    }
  }

  return grants
}

function parseCredentialOfferSchemeAndBaseUri(scheme?: string, baseUri?: string, credentialIssuer?: string): { scheme: string; baseUri: string } {
  const newScheme = scheme?.replace('://', '') ?? (baseUri?.includes('://') ? baseUri.split('://')[0] : 'openid-credential-offer')
  let newBaseUri: string

  if (baseUri) {
    newBaseUri = baseUri
  } else if (newScheme.startsWith('http')) {
    if (credentialIssuer) {
      newBaseUri = credentialIssuer
      if (!newBaseUri.startsWith(`${newScheme}://`)) {
        throw Error(`scheme ${newScheme} is different from base uri ${newBaseUri}`)
      }
    } else {
      throw Error(`A '${newScheme}' scheme requires a URI to be present as baseUri`)
    }
  } else {
    newBaseUri = ''
  }
  newBaseUri = newBaseUri?.replace(`${newScheme}://`, '')

  return { scheme: newScheme, baseUri: newBaseUri }
}

export function createCredentialOfferObject(
  issuerMetadata?: CredentialIssuerMetadataOptsV1_0_15,
  // todo: probably it's wise to create another builder for CredentialOfferPayload that will generate different kinds of CredentialOfferPayload
  opts?: {
    credentialOffer?: CredentialOfferPayloadV1_0_15
    credentialOfferUri?: string
    grants?: CredentialOfferGrantInput
    client_id?: string
  },
): AssertedUniformCredentialOffer {
  if (!issuerMetadata && !opts?.credentialOffer && !opts?.credentialOfferUri) {
    throw new Error('You have to provide issuerMetadata or credentialOffer object for creating a deeplink')
  }

  const grants = createCredentialOfferGrants(opts?.grants)

  let credential_offer: CredentialOfferPayloadV1_0_15
  if (opts?.credentialOffer) {
    credential_offer = {
      ...opts.credentialOffer,
    }
  } else {
    if (!issuerMetadata?.credential_configurations_supported) {
      throw new Error('credential_configurations_supported is mandatory in the metadata')
    }
    credential_offer = {
      credential_issuer: issuerMetadata.credential_issuer,
      credential_configuration_ids: Object.keys(issuerMetadata.credential_configurations_supported),
    }
  }

  if (grants) {
    credential_offer.grants = grants
  }
  if (opts?.client_id) {
    credential_offer.client_id = opts.client_id
  }

  // todo: check payload against issuer metadata. Especially strings in the credentials array: When processing, the Wallet MUST resolve this string value to the respective object.
  return { credential_offer, credential_offer_uri: opts?.credentialOfferUri }
}

export function createCredentialOfferURIFromObject(
  credentialOffer: CredentialOfferV1_0_15 | UniformCredentialOffer,
  offerMode: CredentialOfferMode,
  opts?: { scheme?: string; baseUri?: string },
) {
  const { scheme, baseUri } = parseCredentialOfferSchemeAndBaseUri(opts?.scheme, opts?.baseUri, credentialOffer.credential_offer?.credential_issuer)

  if (offerMode === 'REFERENCE') {
    if (!credentialOffer.credential_offer_uri) {
      throw Error(`credential_offer_uri must be set for offerMode ${offerMode}`)
    }
    if (credentialOffer.credential_offer_uri.includes('credential_offer_uri=')) {
      // discard the scheme. Apparently a URI is set and it already contains the actual uri, so assume that takes priority
      return credentialOffer.credential_offer_uri
    }
    return `${scheme}://${baseUri}?credential_offer_uri=${encodeURIComponent(credentialOffer.credential_offer_uri)}`
  } else if (offerMode === 'VALUE') {
    return `${scheme}://${baseUri}?credential_offer=${encodeURIComponent(JSON.stringify(credentialOffer.credential_offer))}`
  }
  throw Error(`unsupported offerMode ${offerMode}`)
}

export function createCredentialOfferURI(
  offerMode: CredentialOfferMode,
  issuerMetadata?: IssuerMetadataV1_0_15,
  // todo: probably it's wise to create another builder for CredentialOfferPayload that will generate different kinds of CredentialOfferPayload
  opts?: {
    credentialOffer?: CredentialOfferPayloadV1_0_15
    credentialOfferUri?: string
    scheme?: string
    baseUri?: string
    grants?: CredentialOfferGrantInput
  },
): string {
  const credentialOffer = createCredentialOfferObject(issuerMetadata, opts)
  return createCredentialOfferURIFromObject(credentialOffer, offerMode, opts)
}

export const isPreAuthorizedCodeExpired = (state: CredentialOfferSession, expirationDurationInSeconds: number) => {
  const now = +new Date()
  const expirationTime = state.createdAt + expirationDurationInSeconds * 1000
  return now >= expirationTime
}

export const assertValidPinNumber = (pin?: string, pinLength?: number) => {
  if (pin && !RegExp(`[\\d\\D]{${pinLength ?? 6}}`).test(pin)) {
    throw Error(`${PIN_NOT_MATCH_ERROR}`)
  }
}

/**
 * Generates unique credential identifiers for authorization details
 * Each identifier represents a specific credential instance that can be issued
 */
export const generateCredentialIdentifiers = (authDetail: AuthorizationDetailsV1_0_15, session: CredentialOfferSession): string[] => {
  if (typeof authDetail === 'string') {
    return [uuidv4()]
  }

  const identifiers: string[] = []

  if (authDetail.credential_configuration_id) {
    const configId = authDetail.credential_configuration_id
    const hasConfig = session.credentialOffer.credential_offer.credential_configuration_ids?.includes(configId)

    if (hasConfig) {
      identifiers.push(`${configId}_${Date.now()}_${uuidv4()}`)
    }
  }

  if (identifiers.length === 0 && authDetail.format) {
    identifiers.push(`${authDetail.format}_${Date.now()}_${uuidv4()}`)
  }

  // Ultimate fallback
  if (identifiers.length === 0) {
    identifiers.push(uuidv4())
  }

  return identifiers
}
