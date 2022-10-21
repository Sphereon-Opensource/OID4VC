import { getJson, NotFoundError } from './functions';
import {
  EndpointMetadata,
  IssuanceInitiationRequestPayload,
  IssuanceInitiationWithBaseUrl,
  OAuth2ASMetadata,
  Oauth2ASWithOID4VCIMetadata,
  OID4VCIServerMetadata,
  WellKnownEndpoints,
} from './types';

export class MetadataClient {
  public static async;

  public static async retrieveAllMetadataFromInitiation(initiation: IssuanceInitiationWithBaseUrl): Promise<EndpointMetadata> {
    return MetadataClient.retrieveAllMetadataFromInitiationRequest(initiation.issuanceInitiationRequest);
  }

  public static async retrieveAllMetadataFromInitiationRequest(initiationRequest: IssuanceInitiationRequestPayload): Promise<EndpointMetadata> {
    return MetadataClient.retrieveAllMetadata(initiationRequest.issuer);
  }

  public static async retrieveAllMetadata(host: string): Promise<EndpointMetadata> {
    let token_endpoint;
    let credential_endpoint;
    let oid4vciMetadata = await MetadataClient.retrieveOID4VCIServerMetadata(host);

    if (oid4vciMetadata) {
      credential_endpoint = oid4vciMetadata.credential_endpoint;
      token_endpoint = oid4vciMetadata.token_endpoint;
      if (!token_endpoint && oid4vciMetadata.auth_service) {
        // Crossword uses this to separate the AS metadata. We fail when not found, since we now have no way of getting the token endpoint
        const asMetadata: OAuth2ASMetadata = await this.retrieveWellknown(oid4vciMetadata.auth_service, WellKnownEndpoints.OAUTH_AS, {
          errorOnNotFound: true,
        });
        token_endpoint = asMetadata?.token_endpoint;
      }
    } else {
      // No specific OID4VCI endpoint. Either can be an OAuth2 AS or an OpenID IDP. Let's start with OIDC first
      let asConfig: Oauth2ASWithOID4VCIMetadata = await MetadataClient.retrieveWellknown(host, WellKnownEndpoints.OIDC_CONFIGURATION, {
        errorOnNotFound: false,
      });
      if (!asConfig) {
        // Now oAuth2
        asConfig = await MetadataClient.retrieveWellknown(host, WellKnownEndpoints.OAUTH_AS, { errorOnNotFound: false });
      }
      if (asConfig) {
        oid4vciMetadata = asConfig; // TODO: Strip other info?
        credential_endpoint = oid4vciMetadata.credential_endpoint;
        token_endpoint = oid4vciMetadata.token_endpoint;
      }
    }
    if (!token_endpoint) {
      throw new Error(`Could not deduce the token endpoint for ${host}`);
    } else if (!credential_endpoint) {
      throw new Error(`Could not deduce the credential endpoint for ${host}`);
    }
    return {
      token_endpoint,
      credential_endpoint,
      oid4vci_metadata: oid4vciMetadata,
    };
  }

  public static async retrieveOID4VCIServerMetadata(issuer: string): Promise<OID4VCIServerMetadata | undefined> {
    // Since the server metadata endpoint is optional we are not going to throw an error.
    return MetadataClient.retrieveWellknown(issuer, WellKnownEndpoints.OIDC4VCI, { errorOnNotFound: false });
  }

  public static async retrieveWellknown<T>(
    host: string,
    endpointType: WellKnownEndpoints,
    opts?: { errorOnNotFound?: boolean }
  ): Promise<T | undefined> {
    try {
      return await getJson(`${host}${endpointType}`);
    } catch (error) {
      if (!opts?.errorOnNotFound && error instanceof NotFoundError) {
        return undefined;
      }
      throw error;
    }
  }
}
