import {IssuanceInitiationRequestPayload} from "./CredentialIssuance.types";

export interface CredentialOffer {
  baseUrl: string;
}

export interface CredentialOfferWithBaseURL extends CredentialOffer {
  credentialOfferPayload: IssuanceInitiationRequestPayload;
}
