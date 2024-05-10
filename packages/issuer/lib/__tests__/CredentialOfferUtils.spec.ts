import { CredentialOfferPayloadV1_0_13 } from '@sphereon/oid4vci-common'

import { createCredentialOfferURI } from '../index'

describe('CredentialOfferUtils should', () => {
  it('create a deeplink from credentialOffer object', () => {
    // below is the example from spec (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-sending-credential-offer-by) and is wrong, the issuer_state should be in the grants and not a top-level property
    // openid-credential-offer://credential_offer=%7B%22credential_issuer%22:%22https://credential-issuer.example.com%22,%22credentials%22:%5B%7B%22format%22:%22jwt_vc_json%22,%22types%22:%5B%22VerifiableCredential%22,%22UniversityDegreeCredential%22%5D%7D%5D,%22issuer_state%22:%22eyJhbGciOiJSU0Et...FYUaBy%22%7D
    const credentialOffer = {
      credential_issuer: 'https://credential-issuer.example.com',
      credential_configuration_ids: ['UniversityDegreeCredential'],
      grants: {
        authorization_code: {
          issuer_state: 'eyJhbGciOiJSU0Et...FYUaBy',
        },
      },
    } as CredentialOfferPayloadV1_0_13
    expect(createCredentialOfferURI(undefined, { credentialOffer, state: 'eyJhbGciOiJSU0Et...FYUaBy' })).toEqual(
      'openid-credential-offer://?credential_offer=%7B%22credential_issuer%22%3A%22https%3A%2F%2Fcredential-issuer.example.com%22%2C%22credential_configuration_ids%22%3A%5B%22UniversityDegreeCredential%22%5D%2C%22grants%22%3A%7B%22authorization_code%22%3A%7B%22issuer_state%22%3A%22eyJhbGciOiJSU0Et...FYUaBy%22%7D%7D%7D',
    )
  })
})
