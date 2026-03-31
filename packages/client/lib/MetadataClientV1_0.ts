import {
  AuthorizationServerMetadata,
  AuthorizationServerType,
  CredentialIssuerMetadataV1_0,
  CredentialOfferPayloadV1_0,
  CredentialOfferRequestWithBaseUrl,
  EndpointMetadataResultV1_0,
  getIssuerFromCredentialOfferPayload,
  IssuerMetadataV1_0,
  OpenIDResponse,
  processSignedMetadata,
  SignedMetadataVerifyCallback,
  WellKnownEndpoints,
} from '@sphereon/oid4vci-common'
import { Loggers } from '@sphereon/ssi-types'

import { retrieveWellknown } from './functions'

const logger = Loggers.DEFAULT.get('sphereon:oid4vci:metadata')

export class MetadataClientV1_0 {
  public static async retrieveAllMetadataFromCredentialOffer(
    credentialOffer: CredentialOfferRequestWithBaseUrl,
  ): Promise<EndpointMetadataResultV1_0> {
    return MetadataClientV1_0.retrieveAllMetadataFromCredentialOfferRequest(credentialOffer.credential_offer as CredentialOfferPayloadV1_0)
  }

  public static async retrieveAllMetadataFromCredentialOfferRequest(request: CredentialOfferPayloadV1_0): Promise<EndpointMetadataResultV1_0> {
    const issuer = getIssuerFromCredentialOfferPayload(request)
    if (issuer) {
      return MetadataClientV1_0.retrieveAllMetadata(issuer)
    }
    throw new Error("can't retrieve metadata from CredentialOfferRequest. No issuer field is present")
  }

  public static async retrieveAllMetadata(
    issuer: string,
    opts?: {
      errorOnNotFound?: boolean
      signedMetadataVerifyCallback?: SignedMetadataVerifyCallback
    },
  ): Promise<EndpointMetadataResultV1_0> {
    let token_endpoint: string | undefined
    let credential_endpoint: string | undefined
    let nonce_endpoint: string | undefined
    let deferred_credential_endpoint: string | undefined
    let notification_endpoint: string | undefined
    let authorization_endpoint: string | undefined
    let authorization_challenge_endpoint: string | undefined
    let authorizationServerType: AuthorizationServerType = 'OID4VCI'
    let authorization_servers: string[] = [issuer]
    const oid4vciResponse = await MetadataClientV1_0.retrieveOpenID4VCIServerMetadata(issuer, { errorOnNotFound: false })
    let credentialIssuerMetadata = oid4vciResponse?.successBody
    if (credentialIssuerMetadata) {
      logger.debug(`Issuer ${issuer} OID4VCI well-known server metadata\r\n${JSON.stringify(credentialIssuerMetadata)}`)
      credential_endpoint = credentialIssuerMetadata.credential_endpoint
      nonce_endpoint = credentialIssuerMetadata.nonce_endpoint
      deferred_credential_endpoint = credentialIssuerMetadata.deferred_credential_endpoint
      notification_endpoint = credentialIssuerMetadata.notification_endpoint
      if (credentialIssuerMetadata.token_endpoint) {
        token_endpoint = credentialIssuerMetadata.token_endpoint
      }
      authorization_challenge_endpoint = credentialIssuerMetadata.authorization_challenge_endpoint
      if (credentialIssuerMetadata.authorization_servers) {
        authorization_servers = credentialIssuerMetadata.authorization_servers
      }
    }
    let response: OpenIDResponse<AuthorizationServerMetadata> = await retrieveWellknown(
      authorization_servers[0],
      WellKnownEndpoints.OPENID_CONFIGURATION,
      { errorOnNotFound: false },
    )
    let authMetadata = response.successBody
    if (authMetadata) {
      logger.debug(`Issuer ${issuer} has OpenID Connect Server metadata in well-known location`)
      authorizationServerType = 'OIDC'
    } else {
      response = await retrieveWellknown(authorization_servers[0], WellKnownEndpoints.OAUTH_AS, { errorOnNotFound: false })
      authMetadata = response.successBody
    }
    if (!authMetadata) {
      if (!authorization_servers.includes(issuer)) {
        throw Error(`Issuer ${issuer} provided a separate authorization server ${authorization_servers}, but that server did not provide metadata`)
      }
    } else {
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
      if (authMetadata.notification_endpoint) {
        if (notification_endpoint && authMetadata.notification_endpoint !== notification_endpoint) {
          logger.debug(
            `Credential issuer has a different notification_endpoint (${notification_endpoint}) from the Authorization Server (${authMetadata.notification_endpoint}). Will use the issuer value`,
          )
        } else {
          notification_endpoint = authMetadata.notification_endpoint
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
      credentialIssuerMetadata = authMetadata as CredentialIssuerMetadataV1_0
    }

    const ci = (credentialIssuerMetadata ?? {}) as Partial<CredentialIssuerMetadataV1_0>
    const ciAuthorizationServers =
      Array.isArray(ci.authorization_servers) && ci.authorization_servers.length > 0 ? ci.authorization_servers : authorization_servers

    const v1_0CredentialIssuerMetadata: CredentialIssuerMetadataV1_0 = {
      credential_issuer: ci.credential_issuer ?? issuer,
      credential_endpoint: credential_endpoint as string,
      authorization_servers: ciAuthorizationServers,
      credential_configurations_supported: ci.credential_configurations_supported ?? {},
      display: ci.display ?? [],
      ...(nonce_endpoint && { nonce_endpoint }),
      ...(deferred_credential_endpoint && { deferred_credential_endpoint }),
      ...(notification_endpoint && { notification_endpoint }),
      ...(ci.batch_credential_issuance_supported !== undefined && { batch_credential_issuance_supported: ci.batch_credential_issuance_supported }),
      ...(ci.credential_issuer_public_key && { credential_issuer_public_key: ci.credential_issuer_public_key }),
      ...(ci.signed_metadata && { signed_metadata: ci.signed_metadata }),
    }

    logger.debug(`Issuer ${issuer} token endpoint ${token_endpoint}, credential endpoint ${credential_endpoint}`)

    // Process signed_metadata if present and a verify callback is provided
    const processedMetadata = await processSignedMetadata({
      metadata: v1_0CredentialIssuerMetadata,
      issuer,
      signedMetadataVerifyCallback: opts?.signedMetadataVerifyCallback,
    })

    return {
      issuer,
      token_endpoint,
      credential_endpoint,
      authorization_challenge_endpoint,
      notification_endpoint,
      authorizationServerType,
      credentialIssuerMetadata: processedMetadata,
      authorizationServerMetadata: authMetadata,
    }
  }

  public static async retrieveOpenID4VCIServerMetadata(
    issuerHost: string,
    opts?: {
      errorOnNotFound?: boolean
    },
  ): Promise<OpenIDResponse<IssuerMetadataV1_0> | undefined> {
    return retrieveWellknown(issuerHost, WellKnownEndpoints.OPENID4VCI_ISSUER, {
      errorOnNotFound: opts?.errorOnNotFound === undefined ? true : opts.errorOnNotFound,
    })
  }
}
