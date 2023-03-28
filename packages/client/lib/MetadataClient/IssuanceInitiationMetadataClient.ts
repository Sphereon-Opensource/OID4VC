import { EndpointMetadata, IssuanceInitiationRequestPayload, IssuanceInitiationWithBaseUrl } from '@sphereon/openid4vci-common';

import { MetadataClient } from './MetadataClient';

export class IssuanceInitiationMetadataClient extends MetadataClient {
  /**
   * Retrieve metadata using the Initiation obtained from a previous step
   *
   * @param initiation
   */
  public static async getServerMetaData(initiation: IssuanceInitiationWithBaseUrl): Promise<EndpointMetadata> {
    return IssuanceInitiationMetadataClient.getServerFromInitiationRequest(initiation.issuanceInitiationRequest);
  }

  /**
   * Retrieve the metadata using the initiation request obtained from a previous step
   * @param initiationRequest
   */
  public static async getServerFromInitiationRequest(initiationRequest: IssuanceInitiationRequestPayload): Promise<EndpointMetadata> {
    return MetadataClient.retrieveAllMetadata(initiationRequest.issuer);
  }
}
