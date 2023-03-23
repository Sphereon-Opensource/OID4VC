import {OpenId4VCIVersion, URLSchemes} from "@sphereon/openid4vci-common";

import {CredentialOfferIssuance} from "./CredentialOfferIssuance";
import {IssuanceInitiation} from "./IssuanceInitiation";

export interface CredentialOfferClient {
}

export function getStrategy(credentialOfferURI: string): CredentialOfferClient {
  if (OpenId4VCIVersion.VER_9 === getOpenId4VCIVersion(credentialOfferURI)) {
    return IssuanceInitiation.fromURI(credentialOfferURI);
  }

  return CredentialOfferIssuance.fromURI(credentialOfferURI);
}

export function getOpenId4VCIVersion(credentialOfferURI: string): OpenId4VCIVersion {
  if (credentialOfferURI.startsWith(URLSchemes.INITIATE_ISSUANCE)) {
    return OpenId4VCIVersion.VER_9;
  }

  return OpenId4VCIVersion.VER_11
}
