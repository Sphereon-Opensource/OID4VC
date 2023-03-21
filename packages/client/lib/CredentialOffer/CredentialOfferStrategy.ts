import {CredentialOffer, CredentialOfferPayload, EndpointMetadata} from "@sphereon/openid4vci-common";
import {CredentialRequestClientBuilder} from "../CredentialRequestClientBuilder";

export interface CredentialOfferStrategy {
  getCredentialOffer(credentialOfferURI: string): CredentialOffer;
  getServerMetaData(credentialOffer: CredentialOffer): Promise<EndpointMetadata>;
  getCredentialTypes(credentialOffer: CredentialOffer): string[];
  getIssuer(credentialOffer: CredentialOffer): string

  getCredentialRequestClientBuilder(
    credentialOffer: CredentialOfferPayload,
    metadata?: EndpointMetadata): CredentialRequestClientBuilder;

}

