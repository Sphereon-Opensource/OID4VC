import {
  CredentialOfferPayload,
  CredentialOfferRequestWithBaseUrl,
  EndpointMetadata,
  getIssuerFromCredentialOfferPayload,
  IssuerMetadata,
  OAuth2ASMetadata,
  Oauth2ASWithOID4VCIMetadata,
  OpenIDResponse,
  WellKnownEndpoints,
} from '@sphereon/openid4vci-common';
import Debug from 'debug';

import { getJson } from './functions';

const debug = Debug('sphereon:openid4vci:metadata');

export class MetadataClient {
  /**
   * Retrieve metadata using the Initiation obtained from a previous step
   *
   * @param credentialOffer
   */
  public static async retrieveAllMetadataFromCredentialOffer(credentialOffer: CredentialOfferRequestWithBaseUrl): Promise<EndpointMetadata> {
    return MetadataClient.retrieveAllMetadataFromCredentialOfferRequest(credentialOffer.request);
  }

  /**
   * Retrieve the metada using the initiation request obtained from a previous step
   * @param request
   */
  public static async retrieveAllMetadataFromCredentialOfferRequest(request: CredentialOfferPayload): Promise<EndpointMetadata> {
    if (getIssuerFromCredentialOfferPayload(request)) {
      return MetadataClient.retrieveAllMetadata(getIssuerFromCredentialOfferPayload(request) as string);
    }
    throw new Error("can't retrieve metadata from CredentialOfferRequest. No issuer field is present");
  }

  /**
   * Retrieve all metadata from an issuer
   * @param issuer The issuer URL
   * @param opts
   */
  public static async retrieveAllMetadata(issuer: string, opts?: { errorOnNotFound: boolean }): Promise<EndpointMetadata> {
    let token_endpoint;
    let credential_endpoint;
    const response = await MetadataClient.retrieveOpenID4VCIServerMetadata(issuer);
    let issuerMetadata = response?.successBody;
    if (issuerMetadata) {
      debug(`Issuer ${issuer} OID4VCI well-known server metadata\r\n${issuerMetadata}`);
      credential_endpoint = issuerMetadata.credential_endpoint;
      token_endpoint = issuerMetadata.token_endpoint;
      if (!token_endpoint && issuerMetadata.authorization_server) {
        debug(
          `Issuer ${issuer} OID4VCI metadata has separate authorization_server ${issuerMetadata.authorization_server} that contains the token endpoint`
        );
        // Crossword uses this to separate the AS metadata. We fail when not found, since we now have no way of getting the token endpoint
        const response: OpenIDResponse<OAuth2ASMetadata> = await this.retrieveWellknown(
          issuerMetadata.authorization_server,
          WellKnownEndpoints.OAUTH_AS,
          {
            errorOnNotFound: true,
          }
        );
        token_endpoint = response.successBody?.token_endpoint;
      }
    } else {
      // No specific OID4VCI endpoint. Either can be an OAuth2 AS or an OpenID IDP. Let's start with OIDC first
      let response: OpenIDResponse<Oauth2ASWithOID4VCIMetadata> = await MetadataClient.retrieveWellknown(
        issuer,
        WellKnownEndpoints.OPENID_CONFIGURATION,
        {
          errorOnNotFound: false,
        }
      );
      let asConfig = response.successBody;
      if (asConfig) {
        debug(`Issuer ${issuer} has OpenID Connect Server metadata in well-known location`);
      } else {
        // Now oAuth2
        response = await MetadataClient.retrieveWellknown(issuer, WellKnownEndpoints.OAUTH_AS, { errorOnNotFound: false });
        asConfig = response.successBody;
      }
      if (asConfig) {
        debug(`Issuer ${issuer} has oAuth2 Server metadata in well-known location`);
        issuerMetadata = asConfig;
        credential_endpoint = issuerMetadata.credential_endpoint;
        token_endpoint = issuerMetadata.token_endpoint;
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
      issuerMetadata,
    };
  }

  /**
   * Retrieve only the OID4VCI metadata for the issuer. So no OIDC/OAuth2 metadata
   *
   * @param issuerHost The issuer hostname
   */
  public static async retrieveOpenID4VCIServerMetadata(issuerHost: string): Promise<OpenIDResponse<IssuerMetadata> | undefined> {
    // Since the server metadata endpoint is optional we are not going to throw an error.
    return MetadataClient.retrieveWellknown(issuerHost, WellKnownEndpoints.OPENID4VCI_ISSUER, { errorOnNotFound: false });
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
  ): Promise<OpenIDResponse<T>> {
    const result: OpenIDResponse<T> = await getJson(`${host.endsWith('/') ? host.slice(0, -1) : host}${endpointType}`, {
      exceptionOnHttpErrorStatus: opts?.errorOnNotFound,
    });
    if (result.origResponse.status === 404) {
      // We only get here when error on not found is false
      debug(`host ${host} with endpoint type ${endpointType} was not found (404)`);
    }
    return result;
  }
}
