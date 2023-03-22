import {CredentialOffer, CredentialOfferWithBaseURL, EndpointMetadata, OIDCVCIVersion} from "@sphereon/openid4vci-common";

import {CredentialOfferStrategy} from "./CredentialOfferStrategy";

export class CredentialOfferIssuance implements CredentialOfferStrategy {
  readonly version: OIDCVCIVersion;
  private readonly _credentialOfferWithBaseURL: CredentialOfferWithBaseURL;

  public constructor(credentialOfferURI: string) {
    this.version = OIDCVCIVersion.VER_11;
    this._credentialOfferWithBaseURL = this.fromURI(credentialOfferURI);
  }


  public getCredentialOffer(credentialOfferURI: string): CredentialOffer {
    return this.fromURI(credentialOfferURI);
  }

  public fromURI(credentialOfferURI: string): CredentialOfferWithBaseURL {
    throw new Error(`not yet implemented : ${credentialOfferURI}`)
  }

  public async getServerMetaData(): Promise<EndpointMetadata> {
    throw new Error('not yet implemented.')
  }

  public getCredentialTypes(): string[] {
    return [];
  }

  public getIssuer(): string {
    return "";
  }

  public assertIssuerData(): void {
    if (!this._credentialOfferWithBaseURL) {
      throw Error(`No issuance initiation present`);
    }
  }

  get credentialOfferWithBaseURL(): CredentialOfferWithBaseURL {
    return this._credentialOfferWithBaseURL;
  }
}