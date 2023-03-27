import { CredentialOfferWithBaseURL, EndpointMetadata, OpenId4VCIVersion } from '@sphereon/openid4vci-common';
import Debug from 'debug';

import { CredentialIssuanceClient } from './CredentialIssuanceClient';

const debug = Debug('sphereon:openid4vci:credentialOffer');

// FIXME implement the function
export class CredentialOfferClient implements CredentialIssuanceClient {
  public readonly _version: OpenId4VCIVersion;
  private readonly _credentialOfferWithBaseURL: CredentialOfferWithBaseURL;

  private constructor(credentialOfferWithBaseURL: CredentialOfferWithBaseURL) {
    this._version = OpenId4VCIVersion.VER_11;
    this._credentialOfferWithBaseURL = credentialOfferWithBaseURL;
  }

  public static fromURI(credentialOfferURI: string): CredentialOfferClient {
    debug(`'fromURI' is not implemented yet: ${credentialOfferURI}`);
    throw new Error(`'fromURI' is not implemented yet: ${credentialOfferURI}`);
  }

  public static async getServerMetaData(credentialOfferWithBaseURL: CredentialOfferWithBaseURL): Promise<EndpointMetadata> {
    debug(`'getServerMetaData' is not implemented yet: ${JSON.stringify(credentialOfferWithBaseURL)}`);
    throw new Error(`getServerMetaData': Not implemented yet.`);
  }

  public static getCredentialTypes(): string[] {
    throw new Error('getCredentialTypes: Not implemented yet.');
  }

  public static getIssuer(): string {
    throw new Error('getIssuer: Not implemented yet.');
  }

  public static assertIssuerData(credentialOfferWithBaseURL: CredentialOfferWithBaseURL): void {
    if (credentialOfferWithBaseURL) {
      throw Error(`No credential offer present`);
    }
  }

  public assertIssuerData(): void {
    throw new Error('assertIssuerData: Not implemented yet');
  }

  public getCredentialTypes(): string[] {
    throw new Error('getCredentialTypes: Not implemented yet');
  }

  public getIssuer(): string {
    throw new Error('getIssuer: Not implemented yet');
  }

  get credentialOfferWithBaseURL() {
    return this._credentialOfferWithBaseURL;
  }

  get version() {
    return this._version;
  }
}
