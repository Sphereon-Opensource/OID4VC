import {
  AuthorizationServerMetadata,
  AuthorizationServerType,
  CredentialIssuerMetadataV1_0_15,
  CredentialOfferPayload,
  CredentialOfferRequestWithBaseUrl,
  determineSpecVersionFromOffer,
  determineVersionsFromIssuerMetadata,
  EndpointMetadataResult,
  getIssuerFromCredentialOfferPayload,
  OpenId4VCIVersion,
  OpenIDResponse,
  processSignedMetadata,
  SignedMetadataVerifyCallback,
  WellKnownEndpoints,
} from '@sphereon/oid4vci-common'
import { Loggers } from '@sphereon/ssi-types'
import { retrieveWellknown } from './functions'
import { MetadataClientV1_0_15 } from './MetadataClientV1_0_15'

const logger = Loggers.DEFAULT.get('sphereon:oid4vci:metadata')

export class MetadataClient {
  /**
   * Retrieve metadata using the Initiation obtained from a previous step
   *
   * @param credentialOffer
   */
  public static async retrieveAllMetadataFromCredentialOffer(
    credentialOffer: CredentialOfferRequestWithBaseUrl,
  ): Promise<EndpointMetadataResult> {
    const issuer = getIssuerFromCredentialOfferPayload(credentialOffer.credential_offer)
    if (issuer) {
      // Use the generic retrieveAllMetadata which detects version from metadata
      return MetadataClient.retrieveAllMetadata(issuer)
    }
    const openId4VCIVersion = determineSpecVersionFromOffer(credentialOffer.credential_offer)
    if (openId4VCIVersion >= OpenId4VCIVersion.VER_1_0_15) {
      return await MetadataClientV1_0_15.retrieveAllMetadataFromCredentialOffer(credentialOffer)
    }
    return Promise.reject(Error(`OpenId4VCIVersion ${openId4VCIVersion} is not supported in retrieveAllMetadataFromCredentialOffer`))
  }

  /**
   * Retrieve the metada using the initiation request obtained from a previous step
   * @param request
   */
  public static async retrieveAllMetadataFromCredentialOfferRequest(request: CredentialOfferPayload): Promise<EndpointMetadataResult> {
    const issuer = getIssuerFromCredentialOfferPayload(request)
    if (issuer) {
      // Use retrieveAllMetadata which does version detection from issuer metadata
      return MetadataClient.retrieveAllMetadata(issuer)
    }
    throw new Error("can't retrieve metadata from CredentialOfferRequest. No issuer field is present")
  }

  /**
   * Retrieve all metadata from an issuer
   * @param issuer The issuer URL
   * @param opts
   */
  public static async retrieveAllMetadata(
    issuer: string,
    opts?: { errorOnNotFound?: boolean; signedMetadataVerifyCallback?: SignedMetadataVerifyCallback },
  ): Promise<EndpointMetadataResult> {
    let token_endpoint: string | undefined
    let credential_endpoint: string | undefined
    let deferred_credential_endpoint: string | undefined
    let authorization_endpoint: string | undefined
    let authorization_challenge_endpoint: string | undefined
    let authorizationServerType: AuthorizationServerType = 'OID4VCI'
    let authorization_servers: string[] | undefined = [issuer]
    let authorization_server: string | undefined = undefined
    const oid4vciResponse = await MetadataClient.retrieveOpenID4VCIServerMetadata(issuer, { errorOnNotFound: false }) // We will handle errors later, given we will also try other metadata locations
    let credentialIssuerMetadata = oid4vciResponse?.successBody
    if (credentialIssuerMetadata) {
      logger.debug(`Issuer ${issuer} OID4VCI well-known server metadata\r\n${JSON.stringify(credentialIssuerMetadata)}`)
      credential_endpoint = credentialIssuerMetadata.credential_endpoint
      deferred_credential_endpoint = credentialIssuerMetadata.deferred_credential_endpoint
        ? (credentialIssuerMetadata.deferred_credential_endpoint as string)
        : undefined
      if (credentialIssuerMetadata.token_endpoint) {
        token_endpoint = credentialIssuerMetadata.token_endpoint
      }
      authorization_challenge_endpoint = credentialIssuerMetadata.authorization_challenge_endpoint
      if (credentialIssuerMetadata.authorization_servers) {
        authorization_servers = credentialIssuerMetadata.authorization_servers as string[]
      } else if (credentialIssuerMetadata.authorization_server) {
        authorization_server = credentialIssuerMetadata.authorization_server as string
        authorization_servers = [authorization_server]
      }
    } else {
      throw new Error(`Issuer ${issuer} does not expose /.well-known/openid-credential-issuer`)
    }

    // No specific OID4VCI endpoint. Either can be an OAuth2 AS or an OIDC IDP. Let's start with OIDC first
    // TODO: for now we're taking just the first one
    let response: OpenIDResponse<AuthorizationServerMetadata> = await retrieveWellknown(
      authorization_servers[0],
      WellKnownEndpoints.OPENID_CONFIGURATION,
      {
        errorOnNotFound: false,
      },
    )
    let authMetadata = response.successBody
    if (authMetadata) {
      logger.debug(`Issuer ${issuer} has OpenID Connect Server metadata in well-known location`)
      authorizationServerType = 'OIDC'
    } else {
      // Now let's do OAuth2
      // TODO: for now we're taking just the first one
      response = await retrieveWellknown(authorization_servers[0], WellKnownEndpoints.OAUTH_AS, { errorOnNotFound: false })
      authMetadata = response.successBody
    }
    if (!authMetadata) {
      // We will always throw an error, no matter whether the user provided the option not to, because this is bad.
      if (!authorization_servers.includes(issuer)) {
        throw Error(`Issuer ${issuer} provided a separate authorization server ${authorization_servers}, but that server did not provide metadata`)
      }
    } else {
      if (!authorizationServerType) {
        authorizationServerType = 'OAuth 2.0'
      }
      logger.debug(`Issuer ${issuer} has ${authorizationServerType} Server metadata in well-known location`)
      if (!authMetadata.authorization_endpoint) {
        console.warn(
          `Issuer ${issuer} of type ${authorizationServerType} has no authorization_endpoint! Will use ${authorization_endpoint}. This only works for pre-authorized flows`,
        )
      } else if (authorization_endpoint && authMetadata.authorization_endpoint !== authorization_endpoint) {
        throw Error(
          `Credential issuer has a different authorization_endpoint (${authorization_endpoint}) from the Authorization Server (${authMetadata.authorization_endpoint})`,
        )
      }
      authorization_endpoint = authMetadata.authorization_endpoint
      if (authorization_challenge_endpoint && authMetadata.authorization_challenge_endpoint !== authorization_challenge_endpoint) {
        throw Error(
          `Credential issuer has a different authorization_challenge_endpoint (${authorization_challenge_endpoint}) from the Authorization Server (${authMetadata.authorization_challenge_endpoint})`,
        )
      }
      authorization_challenge_endpoint = authMetadata.authorization_challenge_endpoint
      if (!authMetadata.token_endpoint) {
        throw Error(`Authorization Server ${authorization_servers} did not provide a token_endpoint`)
      } else if (token_endpoint && authMetadata.token_endpoint !== token_endpoint) {
        throw Error(
          `Credential issuer has a different token_endpoint (${token_endpoint}) from the Authorization Server (${authMetadata.token_endpoint})`,
        )
      }
      token_endpoint = authMetadata.token_endpoint
      if (authMetadata.credential_endpoint) {
        if (credential_endpoint && authMetadata.credential_endpoint !== credential_endpoint) {
          logger.debug(
            `Credential issuer has a different credential_endpoint (${credential_endpoint}) from the Authorization Server (${authMetadata.credential_endpoint}). Will use the issuer value`,
          )
        } else {
          credential_endpoint = authMetadata.credential_endpoint
        }
      }
      if (authMetadata.deferred_credential_endpoint) {
        if (deferred_credential_endpoint && authMetadata.deferred_credential_endpoint !== deferred_credential_endpoint) {
          logger.debug(
            `Credential issuer has a different deferred_credential_endpoint (${deferred_credential_endpoint}) from the Authorization Server (${authMetadata.deferred_credential_endpoint}). Will use the issuer value`,
          )
        } else {
          deferred_credential_endpoint = authMetadata.deferred_credential_endpoint
        }
      }
    }

    if (!authorization_endpoint) {
      logger.debug(`Issuer ${issuer} does not expose authorization_endpoint, so only pre-auth will be supported`)
    }
    if (!token_endpoint) {
      logger.debug(`Issuer ${issuer} does not have a token_endpoint listed in well-known locations!`)
      if (opts?.errorOnNotFound) {
        throw Error(`Could not deduce the token_endpoint for ${issuer}`)
      } else {
        token_endpoint = `${issuer}${issuer.endsWith('/') ? 'token' : '/token'}`
      }
    }
    if (!credential_endpoint) {
      logger.debug(`Issuer ${issuer} does not have a credential_endpoint listed in well-known locations!`)
      if (opts?.errorOnNotFound) {
        throw Error(`Could not deduce the credential endpoint for ${issuer}`)
      } else {
        credential_endpoint = `${issuer}${issuer.endsWith('/') ? 'credential' : '/credential'}`
      }
    }

    if (!credentialIssuerMetadata && authMetadata) {
      return Promise.reject(Error(`No /.well-known/openid-credential-issuer at ${issuer}.`))
    }
    logger.debug(`Issuer ${issuer} token endpoint ${token_endpoint}, credential endpoint ${credential_endpoint}`)

    // Detect version from the fetched metadata
    const versions = credentialIssuerMetadata ? determineVersionsFromIssuerMetadata(credentialIssuerMetadata) : []
    const detectedVersion = versions.length > 0 ? versions[0] : OpenId4VCIVersion.VER_1_0
    logger.debug(`Detected OID4VCI version ${detectedVersion} for issuer ${issuer}`)

    // Process signed_metadata if present and a verify callback is provided
    const processedMetadata = await processSignedMetadata({
      metadata: credentialIssuerMetadata as CredentialIssuerMetadataV1_0_15,
      issuer,
      signedMetadataVerifyCallback: opts?.signedMetadataVerifyCallback,
    })

    return {
      issuer,
      token_endpoint,
      credential_endpoint,
      deferred_credential_endpoint,
      nonce_endpoint: credentialIssuerMetadata?.nonce_endpoint,
      authorization_servers: authorization_server ? [authorization_server] : (authorization_servers ?? [issuer]),
      authorization_endpoint,
      authorization_challenge_endpoint,
      authorizationServerType,
      credentialIssuerMetadata: processedMetadata as CredentialIssuerMetadataV1_0_15,
      authorizationServerMetadata: authMetadata,
    } as EndpointMetadataResult
  }

  /**
   * Retrieve only the OID4VCI metadata for the issuer. So no OIDC/OAuth2 metadata
   *
   * @param issuerHost The issuer hostname
   * @param opts
   */
  public static async retrieveOpenID4VCIServerMetadata(
    issuerHost: string,
    opts?: {
      errorOnNotFound?: boolean
    },
  ): Promise<OpenIDResponse<CredentialIssuerMetadataV1_0_15> | undefined> {
    return retrieveWellknown(issuerHost, WellKnownEndpoints.OPENID4VCI_ISSUER, {
      errorOnNotFound: opts?.errorOnNotFound === undefined ? true : opts.errorOnNotFound,
    })
  }
}
