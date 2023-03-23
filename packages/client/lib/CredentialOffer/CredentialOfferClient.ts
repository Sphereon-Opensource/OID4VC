import { CredentialOfferWithBaseURL, EndpointMetadata, OpenId4VCIVersion } from '@sphereon/openid4vci-common';
import Debug from 'debug';

import { CredentialIssuanceClient } from './CredentialIssuanceClient';

const debug = Debug('sphereon:openid4vci:credentialOffer');

export class CredentialOfferClient implements CredentialIssuanceClient {
  public readonly _version: OpenId4VCIVersion;
  private readonly _credentialOfferWithBaseURL: CredentialOfferWithBaseURL;

  public constructor(issuanceInitiationURI: string, credentialOfferWithBaseURL: CredentialOfferWithBaseURL) {
    this._version = OpenId4VCIVersion.VER_11;
    this._credentialOfferWithBaseURL = credentialOfferWithBaseURL;
  }

  public static fromURI(credentialOfferURI: string): CredentialOfferClient {
    // FIXME implement the function
    debug(`'fromURI' is not implemented yet: ${credentialOfferURI}`);
    throw new Error(`'fromURI' is not implemented yet: ${credentialOfferURI}`);
  }

  public static async getServerMetaData(credentialOfferWithBaseURL: CredentialOfferWithBaseURL): Promise<EndpointMetadata> {
    throw new Error(`getServerMetaData': Not implemented yet.`);
  }

  public static getCredentialTypes(): string[] {
    return [];
  }

  public static getIssuer(): string {
    return '';
  }

  public static assertIssuerData(credentialOfferWithBaseURL: CredentialOfferWithBaseURL): void {
    if (credentialOfferWithBaseURL) {
      throw Error(`No credential offer present`);
    }
  }

  get credentialOfferWithBaseURL() {
    return this._credentialOfferWithBaseURL;
  }

  get version() {
    return this._version;
  }

  assertIssuerData(): void {
    throw new Error('Not implemented yet');
  }

  getCredentialTypes(): string[] {
    return [];
  }

  getIssuer(): string {
    return '';
  }
}
