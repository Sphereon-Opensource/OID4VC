import {
  AuthorizationServerMetadata,
  AuthorizationServerType,
  CredentialIssuerMetadata,
  CredentialOfferPayload,
  CredentialOfferRequestWithBaseUrl,
  EndpointMetadataResult,
  getIssuerFromCredentialOfferPayload,
  OpenIDResponse,
  WellKnownEndpoints,
} from '@sphereon/oid4vci-common';
import Debug from 'debug';

import { getJson } from './functions';

const debug = Debug('sphereon:oid4vci:metadata');

export class MetadataClient {
  /**
   * Retrieve metadata using the Initiation obtained from a previous step
   *
   * @param credentialOffer
   */
  public static async retrieveAllMetadataFromCredentialOffer(credentialOffer: CredentialOfferRequestWithBaseUrl): Promise<EndpointMetadataResult> {
    return MetadataClient.retrieveAllMetadataFromCredentialOfferRequest(credentialOffer.credential_offer);
  }

  /**
   * Retrieve the metada using the initiation request obtained from a previous step
   * @param request
   */
  public static async retrieveAllMetadataFromCredentialOfferRequest(request: CredentialOfferPayload): Promise<EndpointMetadataResult> {
    const issuer = getIssuerFromCredentialOfferPayload(request); // TODO support multi-hosts?
    if (issuer) {
      return MetadataClient.retrieveAllMetadata([issuer]);
    }
    throw new Error("can't retrieve metadata from CredentialOfferRequest. No issuer field is present");
  }

  /**
   * Retrieve all metadata from an issuer
   * @param issuerHosts The issuer URL
   * @param opts
   */
  public static async retrieveAllMetadata(issuerHosts: string[], opts?: { errorOnNotFound: boolean }): Promise<EndpointMetadataResult> {
    let token_endpoint: string | undefined;
    let credential_endpoint: string | undefined;
    let authorization_endpoint: string | undefined;
    let authorizationServerType: AuthorizationServerType = 'OID4VCI';
    let authorization_servers: string[] = issuerHosts;
    const oid4vciResponse = await MetadataClient.retrieveOpenID4VCIServerMetadata(issuerHosts, { errorOnNotFound: false }); // We will handle errors later, given we will also try other metadata locations
    let issuerHost = oid4vciResponse?.selectedHost
    if (issuerHost) {
      // Move the selected issuerHost to the beginning of the array so teh consecutive calls prefer the same server TODO is this even useful?
      const index = authorization_servers.indexOf(issuerHost);
      if (index > -1) {
        authorization_servers.splice(index, 1);
      }
      authorization_servers.unshift(issuerHost);
    }

    let credentialIssuerMetadata = oid4vciResponse?.successBody;
    if (credentialIssuerMetadata) {
      debug(`Issuer ${issuerHost} OID4VCI well-known server metadata\r\n${JSON.stringify(credentialIssuerMetadata)}`);
      credential_endpoint = credentialIssuerMetadata.credential_endpoint;
      if (credentialIssuerMetadata.token_endpoint) {
        token_endpoint = credentialIssuerMetadata.token_endpoint;
      }
      if (credentialIssuerMetadata.authorization_servers) {
        authorization_servers = credentialIssuerMetadata.authorization_servers;
      }
      if (credentialIssuerMetadata.authorization_endpoint) {
        authorization_endpoint = credentialIssuerMetadata.authorization_endpoint;
      }
    }
    // No specific OID4VCI endpoint. Either can be an OAuth2 AS or an OIDC IDP. Let's start with OIDC first
    let response: OpenIDResponse<AuthorizationServerMetadata> = await MetadataClient.retrieveWellknown(
      authorization_servers,
      WellKnownEndpoints.OPENID_CONFIGURATION,
      {
        errorOnNotFound: false,
      },
    );
    if(response?.selectedHost) {
      issuerHost = response?.selectedHost
    }
    let authMetadata = response.successBody;
    if (authMetadata) {
      debug(`Issuer ${issuerHost} has OpenID Connect Server metadata in well-known location`);
      authorizationServerType = 'OIDC';
    } else {
      // Now let's do OAuth2
      response = await MetadataClient.retrieveWellknown(authorization_servers, WellKnownEndpoints.OAUTH_AS, { errorOnNotFound: false });
      authMetadata = response.successBody;
      if(response?.selectedHost) {
        issuerHost = response?.selectedHost
      }
    }
    if (!authMetadata) {
      // We will always throw an error, no matter whether the user provided the option not to, because this is bad.
      if(!issuerHost) {
        throw Error(`None of provided authorization servers ${authorization_servers} returned a response.`);
      }
      if (!authorization_servers.includes(issuerHost)) {
        throw Error(`Issuer ${issuerHost} provided separate authorization servers ${authorization_servers}, but those servers did not provide metadata`);
      }
    } else {
      if (!authorizationServerType) {
        authorizationServerType = 'OAuth 2.0';
      }
      debug(`Issuer ${issuerHost} has ${authorizationServerType} Server metadata in well-known location`);
      if (!authMetadata.authorization_endpoint) {
        console.warn(
          `Issuer ${issuerHost} of type ${authorizationServerType} has no authorization_endpoint! Will use ${authorization_endpoint}. This only works for pre-authorized flows`,
        );
      } else if (authorization_endpoint && authMetadata.authorization_endpoint !== authorization_endpoint) {
        throw Error(
          `Credential issuer has a different authorization_endpoint (${authorization_endpoint}) from the Authorization Server (${authMetadata.authorization_endpoint})`,
        );
      }
      authorization_endpoint = authMetadata.authorization_endpoint;
      if (!authMetadata.token_endpoint) {
        throw Error(`Authorization Sever ${authorization_servers} did not provide a token_endpoint`);
      } else if (token_endpoint && authMetadata.token_endpoint !== token_endpoint) {
        throw Error(
          `Credential issuer has a different token_endpoint (${token_endpoint}) from the Authorization Server (${authMetadata.token_endpoint})`,
        );
      }
      token_endpoint = authMetadata.token_endpoint;
      if (authMetadata.credential_endpoint) {
        if (credential_endpoint && authMetadata.credential_endpoint !== credential_endpoint) {
          debug(
            `Credential issuer has a different credential_endpoint (${credential_endpoint}) from the Authorization Server (${authMetadata.token_endpoint}). Will use the issuer value`,
          );
        } else {
          credential_endpoint = authMetadata.credential_endpoint;
        }
      }
    }

    if (!authorization_endpoint) {
      debug(`Issuer ${issuerHost} does not expose authorization_endpoint, so only pre-auth will be supported`);
    }
    if (!token_endpoint) {
      debug(`Issuer ${issuerHost} does not have a token_endpoint listed in well-known locations!`);
      if (opts?.errorOnNotFound || !issuerHost) {
        throw Error(`Could not deduce the token_endpoint for ${issuerHost}`);
      } else {
        token_endpoint = `${issuerHost}${issuerHost.endsWith('/') ? 'token' : '/token'}`;
      }
    }
    if (!credential_endpoint) {
      debug(`Issuer ${issuerHost} does not have a credential_endpoint listed in well-known locations!`);
      if (opts?.errorOnNotFound || !issuerHost) {
        throw Error(`Could not deduce the credential endpoint for ${issuerHost}`);
      } else {
        credential_endpoint = `${issuerHost}${issuerHost.endsWith('/') ? 'credential' : '/credential'}`;
      }
    }

    if (!credentialIssuerMetadata && authMetadata) {
      // Apparently everything worked out and the issuer is exposing everything in oAuth2/OIDC well-knowns. Spec is vague about this situation, but we can support it
      credentialIssuerMetadata = authMetadata as CredentialIssuerMetadata;
    }
    if(!issuerHost) {
      throw Error(`None of provided authorization servers ${authorization_servers} returned a response.`);
    }
    debug(`Issuer ${issuerHost} token endpoint ${token_endpoint}, credential endpoint ${credential_endpoint}`);
    return {
      issuer: issuerHost,
      token_endpoint,
      credential_endpoint,
      authorization_servers: authorization_servers,
      authorization_endpoint,
      authorizationServerType,
      credentialIssuerMetadata: credentialIssuerMetadata,
      authorizationServerMetadata: authMetadata,
    };
  }

  /**
   * Retrieve only the OID4VCI metadata for the issuer. So no OIDC/OAuth2 metadata
   *
   * @param issuerHosts The issuer hostname
   */
  public static async retrieveOpenID4VCIServerMetadata(
    issuerHosts: string[],
    opts?: {
      errorOnNotFound?: boolean;
    },
  ): Promise<OpenIDResponse<CredentialIssuerMetadata> | undefined> {
    return MetadataClient.retrieveWellknown(issuerHosts, WellKnownEndpoints.OPENID4VCI_ISSUER, {
      errorOnNotFound: opts?.errorOnNotFound === undefined ? true : opts.errorOnNotFound,
    });
  }

  /**
   * Allows to retrieve information from a well-known location
   *
   * @param hosts The list hosts
   * @param endpointType The endpoint type, currently supports OID4VCI, OIDC and OAuth2 endpoint types
   * @param opts Options, like for instance whether an error should be thrown in case the endpoint doesn't exist
   */

  public static async retrieveWellknown<T>(
    hosts: string[],
    endpointType: WellKnownEndpoints,
    opts?: { errorOnNotFound?: boolean }
  ): Promise<OpenIDResponse<T>> {
    let lastError: string | undefined;

    for (const host of hosts) {
      try {
        const result: OpenIDResponse<T> = await getJson(`${host.endsWith('/') ? host.slice(0, -1) : host}${endpointType}`, {
          exceptionOnHttpErrorStatus: opts?.errorOnNotFound
        });

        if (result.origResponse.status >= 400) {
          debug(`host ${host} with endpoint type ${endpointType} status: ${result.origResponse.status}, ${result.origResponse.statusText}`);
          if (hosts.indexOf(host) < hosts.length - 1) {
            continue; // Try the next host
          }
        }
        result.selectedHost = host
        return result;
      } catch (error) {
        let message: string;
        if (error instanceof Error) {
          message = `host ${host} error: ${error.message}`;
        } else {
          message = `host ${host} encountered an unknown error`;
        }
        if (!lastError) {
          lastError = message;
        } else {
          lastError += `\r\n${message}`;
        }
      }
    }

    if (lastError) {
      throw lastError;
    } else {
      throw new Error('All hosts failed to retrieve well-known endpoint');
    }
  }
}
