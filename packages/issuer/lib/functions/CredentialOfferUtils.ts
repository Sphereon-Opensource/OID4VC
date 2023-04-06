import { CredentialOfferPayload, CredentialOfferPayloadV1_0_11, encodeJsonAsURI, IssuerMetadata } from '@sphereon/openid4vci-common'
import { v4 as uuidv4 } from 'uuid'

export function createCredentialOfferURI(
  issuerMetadata?: IssuerMetadata,
  // todo: probably it's wise to create another builder for CredentialOfferPayload that will generate different kinds of CredentialOfferPayload
  opts?: {
    state?: string
    credentialOffer?: CredentialOfferPayload
    credentialOfferUri?: string
    scheme?: string
    preAuthorizedCode?: string
    userPinRequired?: boolean
  }
): string {
  if (!issuerMetadata && !opts?.credentialOffer && !opts?.credentialOfferUri) {
    throw new Error('You have to provide issuerMetadata or credentialOffer object for creating a deeplink')
  }
  const scheme = opts?.scheme ? opts.scheme : 'openid-credential-offer'
  if (opts?.credentialOfferUri) {
    return `${scheme}://?credential_offer_uri=${opts?.credentialOfferUri}`
  }
  if (opts?.credentialOffer) {
    return `${scheme}://?credential_offer=${encodeJsonAsURI(opts.credentialOffer)}`
  }
  const credentialOfferPayload = {
    credential_issuer: issuerMetadata?.credential_issuer,
    credentials: issuerMetadata?.credentials_supported,
    grants: {
      authorization_code: {
        issuer_state: opts && opts.state ? opts.state : uuidv4(),
      },
    },
  } as CredentialOfferPayloadV1_0_11
  if (opts?.preAuthorizedCode) {
    if (!credentialOfferPayload.grants) {
      credentialOfferPayload.grants = {}
    }
    credentialOfferPayload.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'] = {
      'pre-authorized_code': opts.preAuthorizedCode,
      user_pin_required: opts.userPinRequired ? opts.userPinRequired : false,
    }
  }
  return `${scheme}://?credential_offer=${encodeJsonAsURI(credentialOfferPayload)}`
}
