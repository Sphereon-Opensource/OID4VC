import Debug from 'debug';

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

const debug = Debug('sphereon:oid4vci:metadata');

export class MetadataClient {
  public static async;

  /**
   * Retrieve metadata using the Initiation obtained from a previous step
   *
   * @param initiation
   */
  public static async retrieveAllMetadataFromInitiation(initiation: IssuanceInitiationWithBaseUrl): Promise<EndpointMetadata> {
    return MetadataClient.retrieveAllMetadataFromInitiationRequest(initiation.issuanceInitiationRequest);
  }

  /**
   * Retrieve the metada using the initiation request obtained from a previous step
   * @param initiationRequest
   */
  public static async retrieveAllMetadataFromInitiationRequest(initiationRequest: IssuanceInitiationRequestPayload): Promise<EndpointMetadata> {
    return MetadataClient.retrieveAllMetadata(initiationRequest.issuer);
  }

  /**
   * Retrieve all metadata from an issuer
   * @param issuer The issuer URL
   */
  public static async retrieveAllMetadata(issuer: string, opts?: { errorOnNotFound: boolean }): Promise<EndpointMetadata | undefined> {
    let token_endpoint;
    let credential_endpoint;
    let oid4vciMetadata = await MetadataClient.retrieveOID4VCIServerMetadata(issuer);

    if (oid4vciMetadata) {
      debug(`Issuer ${issuer} OID4VCI well-known server metadata\r\n${oid4vciMetadata}`);
      credential_endpoint = oid4vciMetadata.credential_endpoint;
      token_endpoint = oid4vciMetadata.token_endpoint;
      if (!token_endpoint && oid4vciMetadata.authorization_server) {
        debug(
          `Issuer ${issuer} OID4VCI metadata has separate authorization_server ${oid4vciMetadata.authorization_server} that contains the token endpoint`
        );
        // Crossword uses this to separate the AS metadata. We fail when not found, since we now have no way of getting the token endpoint
        const asMetadata: OAuth2ASMetadata = await this.retrieveWellknown(oid4vciMetadata.authorization_server, WellKnownEndpoints.OAUTH_AS, {
          errorOnNotFound: true,
        });
        token_endpoint = asMetadata?.token_endpoint;
      }
    } else {
      // No specific OID4VCI endpoint. Either can be an OAuth2 AS or an OpenID IDP. Let's start with OIDC first
      let asConfig: Oauth2ASWithOID4VCIMetadata = await MetadataClient.retrieveWellknown(issuer, WellKnownEndpoints.OIDC_CONFIGURATION, {
        errorOnNotFound: false,
      });
      if (asConfig) {
        debug(`Issuer ${issuer} has OpenID Connect Server metadata in well-known location`);
      } else {
        // Now oAuth2
        asConfig = await MetadataClient.retrieveWellknown(issuer, WellKnownEndpoints.OAUTH_AS, { errorOnNotFound: false });
      }
      if (asConfig) {
        debug(`Issuer ${issuer} has oAuth2 Server metadata in well-known location`);
        oid4vciMetadata = asConfig; // TODO: Strip other info?
        credential_endpoint = oid4vciMetadata.credential_endpoint;
        token_endpoint = oid4vciMetadata.token_endpoint;
      }
    }
    if (!token_endpoint) {
      debug(`Issuer ${issuer} does not have a token_endpoint listed in well-known locations!`);
      if (opts?.errorOnNotFound) {
        throw new Error(`Could not deduce the token endpoint for ${issuer}`);
      } else {
        token_endpoint = `${issuer}${issuer.endsWith('/') ? '' : '/'}token`;
      }
    }
    if (!credential_endpoint) {
      debug(`Issuer ${issuer} does not have a credential_endpoint listed in well-known locations!`);
      if (opts?.errorOnNotFound) {
        throw new Error(`Could not deduce the credential endpoint for ${issuer}`);
      } else {
        credential_endpoint = `${issuer}${issuer.endsWith('/') ? '' : '/'}credential`;
      }
    }
    debug(`Issuer ${issuer} token endpoint ${token_endpoint}, credential endpoint ${credential_endpoint}`);
    return {
      issuer,
      token_endpoint,
      credential_endpoint,
      oid4vci_metadata: oid4vciMetadata,
    };
  }

  /**
   * Retrieve only the OID4VCI metadata for the issuer. So no OIDC/OAuth2 metadata
   *
   * @param issuerHost The issuer hostname
   */
  public static async retrieveOID4VCIServerMetadata(issuerHost: string): Promise<OID4VCIServerMetadata | undefined> {
    // Since the server metadata endpoint is optional we are not going to throw an error.
    return MetadataClient.retrieveWellknown(issuerHost, WellKnownEndpoints.OIDC4VCI, { errorOnNotFound: false });
  }

  /**
   * Allows to retrieve information from a well-known location
   *
   * @param host The host
   * @param endpointType The endpoint type, currently supports OID4VCI, OIDC and OAuth2 endpoint types
   * @param opts Options, like for instance whether an error should be thrown in case the endpoint doesn't exist
   */
  public static async retrieveWellknown<T>(
    host: string,
    endpointType: WellKnownEndpoints,
    opts?: { errorOnNotFound?: boolean }
  ): Promise<T | undefined> {
    try {
      return await getJson(`${host.endsWith('/') ? host.slice(0, -1) : host}${endpointType}`);
    } catch (error) {
      if (!opts?.errorOnNotFound && error instanceof NotFoundError) {
        return undefined;
      }
      throw error;
    }
  }
}
