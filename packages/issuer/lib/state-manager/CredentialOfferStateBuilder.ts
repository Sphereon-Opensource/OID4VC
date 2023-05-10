import { CredentialOfferState, CredentialOfferV1_0_11 } from '@sphereon/oid4vci-common'

export class CredentialOfferStateBuilder {
  private readonly credentialOfferState: Partial<CredentialOfferState>
  constructor() {
    this.credentialOfferState = {}
  }

  credentialOffer(credentialOffer: CredentialOfferV1_0_11): CredentialOfferStateBuilder {
    this.credentialOfferState.credentialOffer = credentialOffer
    return this
  }

  createdOn(timestamp: number): CredentialOfferStateBuilder {
    this.credentialOfferState.createdOn = timestamp
    return this
  }

  build(): CredentialOfferState {
    if (!this.credentialOfferState.createdOn) {
      this.credentialOfferState.createdOn = +new Date()
    }
    if (!this.credentialOfferState.credentialOffer) {
      throw new Error('Not all properties are present to build an IssuerState object')
    }
    return this.credentialOfferState as CredentialOfferState
  }
}
