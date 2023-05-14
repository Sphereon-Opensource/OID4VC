import { CredentialIssuerMetadata, CredentialOfferPayloadV1_0_11, CredentialOfferV1_0_11, encodeJsonAsURI, Grant } from '@sphereon/oid4vci-common'
import { v4 as uuidv4 } from 'uuid'

export function createCredentialOfferObject(
  issuerMetadata?: CredentialIssuerMetadata,
  // todo: probably it's wise to create another builder for CredentialOfferPayload that will generate different kinds of CredentialOfferPayload
  opts?: {
    state?: string
    credentialOffer?: CredentialOfferPayloadV1_0_11
    credentialOfferUri?: string
    scheme?: string
    preAuthorizedCode?: string
    userPinRequired?: boolean
  }
): CredentialOfferV1_0_11 & { scheme: string; grant: Grant } {
  if (!issuerMetadata && !opts?.credentialOffer && !opts?.credentialOfferUri) {
    throw new Error('You have to provide issuerMetadata or credentialOffer object for creating a deeplink')
  }
  const scheme = opts?.scheme ? opts.scheme : 'openid-credential-offer'
  const credential_offer_uri = opts?.credentialOfferUri ? `${scheme}://?credential_offer_uri=${opts?.credentialOfferUri}` : undefined
  let credential_offer: CredentialOfferPayloadV1_0_11
  if (opts?.credentialOffer) {
    credential_offer = opts.credentialOffer
  } else {
    credential_offer = {
      credential_issuer: issuerMetadata?.credential_issuer,
      credentials: issuerMetadata?.credentials_supported,
    } as CredentialOfferPayloadV1_0_11
  }

  if (!credential_offer.grants) {
    credential_offer.grants = {}
  }
  if (opts?.preAuthorizedCode) {
    credential_offer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'] = {
      'pre-authorized_code': opts.preAuthorizedCode,
      user_pin_required: opts.userPinRequired ? opts.userPinRequired : false,
    }
  } else if (!credential_offer.grants?.authorization_code?.issuer_state) {
    credential_offer.grants = {
      authorization_code: {
        issuer_state: opts?.state ?? uuidv4(),
      },
    }
  }
  return { credential_offer, credential_offer_uri, scheme, grant: credential_offer.grants }
}

export function createCredentialOfferURIFromObject(
  credentialOffer: CredentialOfferV1_0_11 & { scheme: string; grant: Grant },
  opts?: { scheme?: string }
) {
  const scheme = opts?.scheme ?? 'openid-credential-offer'
  if (credentialOffer.credential_offer_uri) {
    return `${scheme}://?credential_offer_uri=${credentialOffer.credential_offer_uri}`
  }
  return `${scheme}://?credential_offer=${encodeJsonAsURI(credentialOffer.credential_offer)}`
}

export function createCredentialOfferURI(
  issuerMetadata?: CredentialIssuerMetadata,
  // todo: probably it's wise to create another builder for CredentialOfferPayload that will generate different kinds of CredentialOfferPayload
  opts?: {
    state?: string
    credentialOffer?: CredentialOfferPayloadV1_0_11
    credentialOfferUri?: string
    scheme?: string
    preAuthorizedCode?: string
    userPinRequired?: boolean
  }
): string {
  const credentialOffer = createCredentialOfferObject(issuerMetadata, opts)
  return createCredentialOfferURIFromObject(credentialOffer, opts)
}
