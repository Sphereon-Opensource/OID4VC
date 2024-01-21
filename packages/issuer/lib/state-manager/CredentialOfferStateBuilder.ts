import { AssertedUniformCredentialOffer, CredentialOfferSession } from '@sphereon/oid4vc-common'

export class CredentialOfferStateBuilder {
  private readonly credentialOfferState: Partial<CredentialOfferSession>
  constructor() {
    this.credentialOfferState = {}
  }

  credentialOffer(credentialOffer: AssertedUniformCredentialOffer): CredentialOfferStateBuilder {
    this.credentialOfferState.credentialOffer = credentialOffer
    return this
  }

  createdAt(timestamp: number): CredentialOfferStateBuilder {
    this.credentialOfferState.createdAt = timestamp
    return this
  }

  build(): CredentialOfferSession {
    if (!this.credentialOfferState.createdAt) {
      this.credentialOfferState.createdAt = +new Date()
    }
    if (!this.credentialOfferState.credentialOffer) {
      throw new Error('Not all properties are present to build an IssuerState object')
    }
    return this.credentialOfferState as CredentialOfferSession
  }
}
