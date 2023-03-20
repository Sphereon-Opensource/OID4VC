import {CredentialOffer, CredentialOfferWithBaseURL} from "@sphereon/openid4vci-common";
import {CredentialOfferStrategy} from "./CredentialOfferStrategy";

export class CredentialOfferIssuance implements CredentialOfferStrategy {

  public getCredentialOffer(credentialOfferURI: string): CredentialOffer {
    return this.fromURI(credentialOfferURI);
  }

  public fromURI(credentialOfferURI: string): CredentialOfferWithBaseURL {
    throw new Error('not yet implemented.')
  }
}