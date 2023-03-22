import {EndpointMetadata, OIDCVCIVersion} from "@sphereon/openid4vci-common";
import {IssuanceInitiation} from "./IssuanceInitiation";
import {CredentialOfferIssuance} from "./CredentialOfferIssuance";

export interface CredentialOfferStrategy {
  readonly version: OIDCVCIVersion;
  getServerMetaData(): Promise<EndpointMetadata>;
  getCredentialTypes(): string[];
  getIssuer(): string
  assertIssuerData(): void;
}

export function getStrategy(oidcvciVersion: OIDCVCIVersion, credentialOfferURI: string): CredentialOfferStrategy {
  if(OIDCVCIVersion.VER_9 === oidcvciVersion) {
    return new IssuanceInitiation(credentialOfferURI);
  } else if (OIDCVCIVersion.VER_11 === oidcvciVersion) {
    return new CredentialOfferIssuance(credentialOfferURI);
  }

  throw new Error('unexpected version')
}