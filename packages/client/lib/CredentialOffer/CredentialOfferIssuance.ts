import {
  CredentialOfferWithBaseURL,
  EndpointMetadata,
  OpenId4VCIVersion,
} from "@sphereon/openid4vci-common";

import {CredentialOfferClient} from "./CredentialOfferClient";
import Debug from "debug";

const debug = Debug('sphereon:openid4vci:credentialOffer');

export class CredentialOfferIssuance implements CredentialOfferClient {

  public static readonly version: OpenId4VCIVersion.VER_11;

  public static fromURI(credentialOfferURI: string): CredentialOfferWithBaseURL {
    // FIXME implement the function
    debug(`\'fromURI\' is not implemented yet: ${credentialOfferURI}`);
    throw new Error(`\'fromURI\' is not implemented yet: ${credentialOfferURI}`)
  }

  public static async getServerMetaData(): Promise<EndpointMetadata> {
    throw new Error('\'getServerMetaData\': Not implemented yet.')
  }

  public static getCredentialTypes(): string[] {
    return [];
  }

  public static getIssuer(): string {
    return "";
  }

  public static assertIssuerData(credentialOfferWithBaseURL: CredentialOfferWithBaseURL): void {
    if (credentialOfferWithBaseURL) {
      throw Error(`No credential offer present`);
    }
  }
}