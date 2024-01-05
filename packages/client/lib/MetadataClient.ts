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
    const issuer = getIssuerFromCredentialOfferPayload(request);
    if (issuer) {
      return MetadataClient.retrieveAllMetadata(issuer);
    }
    throw new Error("can't retrieve metadata from CredentialOfferRequest. No issuer field is present");
  }

  /**
   * Retrieve all metadata from an issuer
   * @param issuer The issuer URL
   * @param opts
   */
  public static async retrieveAllMetadata(issuer: string, opts?: { errorOnNotFound: boolean }): Promise<EndpointMetadataResult> {
    let token_endpoint: string | undefined;
    let credential_endpoint: string | undefined;
    let deferred_credential_endpoint: string | undefined;
    let authorization_endpoint: string | undefined;
    let authorizationServerType: AuthorizationServerType = 'OID4VCI';
    let authorization_server: string = issuer;
    const oid4vciResponse = await MetadataClient.retrieveOpenID4VCIServerMetadata(issuer, { errorOnNotFound: false }); // We will handle errors later, given we will also try other metadata locations
    let credentialIssuerMetadata = oid4vciResponse?.successBody;
    if (credentialIssuerMetadata) {
      debug(`Issuer ${issuer} OID4VCI well-known server metadata\r\n${JSON.stringify(credentialIssuerMetadata)}`);
      credential_endpoint = credentialIssuerMetadata.credential_endpoint;
      deferred_credential_endpoint = credentialIssuerMetadata.deferred_credential_endpoint;
      if (credentialIssuerMetadata.token_endpoint) {
        token_endpoint = credentialIssuerMetadata.token_endpoint;
      }
      if (credentialIssuerMetadata.authorization_server) {
        authorization_server = credentialIssuerMetadata.authorization_server;
      }
      if (credentialIssuerMetadata.authorization_endpoint) {
        authorization_endpoint = credentialIssuerMetadata.authorization_endpoint;
      }
    }
    // No specific OID4VCI endpoint. Either can be an OAuth2 AS or an OIDC IDP. Let's start with OIDC first
    let response: OpenIDResponse<AuthorizationServerMetadata> = await MetadataClient.retrieveWellknown(
      authorization_server,
      WellKnownEndpoints.OPENID_CONFIGURATION,
      {
        errorOnNotFound: false,
      },
    );
    let authMetadata = response.successBody;
    if (authMetadata) {
      debug(`Issuer ${issuer} has OpenID Connect Server metadata in well-known location`);
      authorizationServerType = 'OIDC';
    } else {
      // Now let's do OAuth2
      response = await MetadataClient.retrieveWellknown(authorization_server, WellKnownEndpoints.OAUTH_AS, { errorOnNotFound: false });
      authMetadata = response.successBody;
    }
    if (!authMetadata) {
      // We will always throw an error, no matter whether the user provided the option not to, because this is bad.
      if (issuer !== authorization_server) {
        throw Error(`Issuer ${issuer} provided a separate authorization server ${authorization_server}, but that server did not provide metadata`);
      }
    } else {
      if (!authorizationServerType) {
        authorizationServerType = 'OAuth 2.0';
      }
      debug(`Issuer ${issuer} has ${authorizationServerType} Server metadata in well-known location`);
      if (!authMetadata.authorization_endpoint) {
        console.warn(
          `Issuer ${issuer} of type ${authorizationServerType} has no authorization_endpoint! Will use ${authorization_endpoint}. This only works for pre-authorized flows`,
        );
      } else if (authorization_endpoint && authMetadata.authorization_endpoint !== authorization_endpoint) {
        throw Error(
          `Credential issuer has a different authorization_endpoint (${authorization_endpoint}) from the Authorization Server (${authMetadata.authorization_endpoint})`,
        );
      }
      authorization_endpoint = authMetadata.authorization_endpoint;
      if (!authMetadata.token_endpoint) {
        throw Error(`Authorization Sever ${authorization_server} did not provide a token_endpoint`);
      } else if (token_endpoint && authMetadata.token_endpoint !== token_endpoint) {
        throw Error(
          `Credential issuer has a different token_endpoint (${token_endpoint}) from the Authorization Server (${authMetadata.token_endpoint})`,
        );
      }
      token_endpoint = authMetadata.token_endpoint;
      if (authMetadata.credential_endpoint) {
        if (credential_endpoint && authMetadata.credential_endpoint !== credential_endpoint) {
          debug(
            `Credential issuer has a different credential_endpoint (${credential_endpoint}) from the Authorization Server (${authMetadata.credential_endpoint}). Will use the issuer value`,
          );
        } else {
          credential_endpoint = authMetadata.credential_endpoint;
        }
      }
      if (authMetadata.deferred_credential_endpoint) {
        if (deferred_credential_endpoint && authMetadata.deferred_credential_endpoint !== deferred_credential_endpoint) {
          debug(
            `Credential issuer has a different deferred_credential_endpoint (${deferred_credential_endpoint}) from the Authorization Server (${authMetadata.deferred_credential_endpoint}). Will use the issuer value`,
          );
        } else {
          deferred_credential_endpoint = authMetadata.deferred_credential_endpoint;
        }
      }
    }

    if (!authorization_endpoint) {
      debug(`Issuer ${issuer} does not expose authorization_endpoint, so only pre-auth will be supported`);
    }
    if (!token_endpoint) {
      debug(`Issuer ${issuer} does not have a token_endpoint listed in well-known locations!`);
      if (opts?.errorOnNotFound) {
        throw Error(`Could not deduce the token_endpoint for ${issuer}`);
      } else {
        token_endpoint = `${issuer}${issuer.endsWith('/') ? 'token' : '/token'}`;
      }
    }
    if (!credential_endpoint) {
      debug(`Issuer ${issuer} does not have a credential_endpoint listed in well-known locations!`);
      if (opts?.errorOnNotFound) {
        throw Error(`Could not deduce the credential endpoint for ${issuer}`);
      } else {
        credential_endpoint = `${issuer}${issuer.endsWith('/') ? 'credential' : '/credential'}`;
      }
    }

    if (!credentialIssuerMetadata && authMetadata) {
      // Apparently everything worked out and the issuer is exposing everything in oAuth2/OIDC well-knowns. Spec is vague about this situation, but we can support it
      credentialIssuerMetadata = authMetadata as CredentialIssuerMetadata;
    }
    debug(`Issuer ${issuer} token endpoint ${token_endpoint}, credential endpoint ${credential_endpoint}`);
    return {
      issuer,
      token_endpoint,
      credential_endpoint,
      deferred_credential_endpoint,
      authorization_server,
      authorization_endpoint,
      authorizationServerType,
      credentialIssuerMetadata: credentialIssuerMetadata,
      authorizationServerMetadata: authMetadata,
    };
  }

  /**
   * Retrieve only the OID4VCI metadata for the issuer. So no OIDC/OAuth2 metadata
   *
   * @param issuerHost The issuer hostname
   */
  public static async retrieveOpenID4VCIServerMetadata(
    issuerHost: string,
    opts?: {
      errorOnNotFound?: boolean;
    },
  ): Promise<OpenIDResponse<CredentialIssuerMetadata> | undefined> {
    return MetadataClient.retrieveWellknown(issuerHost, WellKnownEndpoints.OPENID4VCI_ISSUER, {
      errorOnNotFound: opts?.errorOnNotFound === undefined ? true : opts.errorOnNotFound,
    });
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
    opts?: { errorOnNotFound?: boolean },
  ): Promise<OpenIDResponse<T>> {
    const result: OpenIDResponse<T> = await getJson(`${host.endsWith('/') ? host.slice(0, -1) : host}${endpointType}`, {
      exceptionOnHttpErrorStatus: opts?.errorOnNotFound,
    });
    if (result.origResponse.status >= 400) {
      // We only get here when error on not found is false
      debug(`host ${host} with endpoint type ${endpointType} status: ${result.origResponse.status}, ${result.origResponse.statusText}`);
    }
    return result;
  }
}
