import {CredentialOffer} from "@sphereon/openid4vci-common";

export interface CredentialOfferStrategy {
  getCredentialOffer(credentialOfferURI: string): CredentialOffer;
}

