import { CredentialOfferV1_0_11, IssuerState } from '@sphereon/openid4vci-common'

export class IssuerStateBuilder {
  private readonly issuerState: Partial<IssuerState>
  constructor() {
    this.issuerState = {}
  }

  credentialOffer(credentialOffer: CredentialOfferV1_0_11): IssuerStateBuilder {
    ;(this.issuerState.credentialOffer as CredentialOfferV1_0_11) = credentialOffer
    return this
  }

  createdOn(timestamp: number): IssuerStateBuilder {
    this.issuerState.createdOn = timestamp
    return this
  }

  build(): IssuerState {
    if (!this.issuerState.credentialOffer || !this.issuerState.createdOn) {
      throw new Error('Not all properties are present to build an IssuerState object')
    }
    return this.issuerState as IssuerState
  }
}
