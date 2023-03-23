import {OpenId4VCIVersion, URLSchemes} from "@sphereon/openid4vci-common";

import {CredentialOfferClient} from "./CredentialOfferClient";
import {IssuanceInitiationClient} from "./IssuanceInitiationClient";

export interface CredentialIssuanceOfferInitiationClient {
  readonly _version: OpenId4VCIVersion;
  getIssuer(): string
  assertIssuerData(): void;
  getCredentialTypes(): string[];
}

export function getStrategy(credentialOfferURI: string): CredentialIssuanceOfferInitiationClient {
  if (OpenId4VCIVersion.VER_9 === getOpenId4VCIVersion(credentialOfferURI)) {
    return IssuanceInitiationClient.fromURI(credentialOfferURI);
  }

  return CredentialOfferClient.fromURI(credentialOfferURI);
}

export function getOpenId4VCIVersion(credentialOfferURI: string): OpenId4VCIVersion {
  if (credentialOfferURI.startsWith(URLSchemes.INITIATE_ISSUANCE)) {
    return OpenId4VCIVersion.VER_9;
  }

  return OpenId4VCIVersion.VER_11
}
