import { CredentialOfferWithBaseURL, EndpointMetadata, ICredentialIssuerMetadataParametersV1_11 } from '@sphereon/openid4vci-common';

import { MetadataClient } from './MetadataClient';

export class CredentialOfferMetadataClient extends MetadataClient {
  /**
   * Retrieve metadata using the credentialOfferWithBaseURL obtained from a previous step
   *
   * @param credentialOfferWithBaseURL
   */
  public static async getServerMetaData(credentialOfferWithBaseURL: CredentialOfferWithBaseURL): Promise<EndpointMetadata> {
    throw new Error('Not implemented yet.');
  }

  /**
   * Retrieve the metadata using the credentialIssuerMetadata request obtained from a previous step
   * @param credentialIssuerMetadata
   */
  public static async getServerFromInitiationRequest(credentialIssuerMetadata: ICredentialIssuerMetadataParametersV1_11): Promise<EndpointMetadata> {
    throw new Error('Not implemented yet.');
  }
}
