import {CredentialOffer, CredentialOfferWithBaseURL, EndpointMetadata} from "@sphereon/openid4vci-common";
import {CredentialOfferStrategy} from "./CredentialOfferStrategy";
import {CredentialRequestClientBuilder} from "../CredentialRequestClientBuilder";

export class CredentialOfferIssuance implements CredentialOfferStrategy {

  public getCredentialOffer(credentialOfferURI: string): CredentialOffer {
    return this.fromURI(credentialOfferURI);
  }

  public fromURI(credentialOfferURI: string): CredentialOfferWithBaseURL {
    throw new Error('not yet implemented.')
  }

  public async getServerMetaData(credentialOfferWithBaseURL: CredentialOfferWithBaseURL): Promise<EndpointMetadata> {
    throw new Error('not yet implemented.')
  }

  public getCredentialTypes(issuanceInitiation: CredentialOffer): string[] {
    return [];
  }

  getIssuer(credentialOffer: CredentialOffer): string {
    return "";
  }

  getCredentialRequestClientBuilder(
    credentialOffer: CredentialOffer,
    metadata?: EndpointMetadata
  ): CredentialRequestClientBuilder {
    throw new Error('not yet implemented.')
  }
}