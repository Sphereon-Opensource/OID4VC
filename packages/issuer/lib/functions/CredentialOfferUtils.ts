import { CredentialOfferPayload, CredentialOfferPayloadV1_0_11, encodeJsonAsURI, IssuerMetadata } from '@sphereon/openid4vci-common'
import { v4 as uuidv4 } from 'uuid'

export function createCredentialOfferDeeplink(
  issuerMetadata?: IssuerMetadata,
  opts?: { state?: string; credentialOffer?: CredentialOfferPayload; preAuthorizedCode?: string; userPinRequired?: boolean }
): string {
  // openid-credential-offer://credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com
  // %22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCr
  // edential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...
  // FYUaBy%22%7D
  if (!issuerMetadata && !opts?.credentialOffer) {
    throw new Error('You have to provide issuerMetadata or credentialOffer object for creating a deeplink')
  }
  if (opts?.credentialOffer) {
    return `openid-credential-offer://?credential_offer=${encodeJsonAsURI(opts.credentialOffer)}`
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
  return `openid-credential-offer://?credential_offer=${encodeJsonAsURI(credentialOfferPayload)}`
}
