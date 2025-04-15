import {
  AuthorizationDetails,
  AuthorizationRequestOpts,
  CodeChallengeMethod,
  convertJsonToURI,
  CreateRequestObjectMode,
  CredentialOfferFormatV1_0_11,
  CredentialOfferPayloadV1_0_11,
  CredentialOfferRequestWithBaseUrl,
  CredentialsSupportedLegacy,
  EndpointMetadataResultV1_0_11,
  formPost,
  JsonURIMode,
  PARMode,
  PKCEOpts,
  PushedAuthorizationResponse,
  ResponseType,
} from '@sphereon/oid4vci-common'
import { Loggers } from '@sphereon/ssi-types'

import { createSignedAuthRequestWhenNeeded } from './AuthorizationCodeClient'

const logger = Loggers.DEFAULT.get('sphereon:oid4vci')

export const createAuthorizationRequestUrlV1_0_11 = async ({
  pkce,
  endpointMetadata,
  authorizationRequest,
  credentialOffer,
  credentialsSupported,
}: {
  pkce: PKCEOpts
  endpointMetadata: EndpointMetadataResultV1_0_11
  authorizationRequest: AuthorizationRequestOpts
  credentialOffer?: CredentialOfferRequestWithBaseUrl
  credentialsSupported?: CredentialsSupportedLegacy[]
}): Promise<string> => {
  const { redirectUri, clientId, requestObjectOpts = { requestObjectMode: CreateRequestObjectMode.NONE } } = authorizationRequest
  let { scope, authorizationDetails } = authorizationRequest

  const parMode = endpointMetadata?.credentialIssuerMetadata?.require_pushed_authorization_requests
    ? PARMode.REQUIRE
    : (authorizationRequest.parMode ?? PARMode.AUTO)
  // Scope and authorization_details can be used in the same authorization request
  // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-rar-23#name-relationship-to-scope-param
  if (!scope && !authorizationDetails) {
    if (!credentialOffer) {
      throw Error('Please provide a scope or authorization_details if no credential offer is present')
    }
    const creds: (CredentialOfferFormatV1_0_11 | string)[] = (credentialOffer.credential_offer as CredentialOfferPayloadV1_0_11).credentials

    // FIXME: complains about VCT for sd-jwt
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    authorizationDetails = creds
      .flatMap((cred) => (typeof cred === 'string' ? credentialsSupported : (cred as CredentialsSupportedLegacy)))
      .filter((cred) => !!cred)
      .map((cred) => {
        return {
          ...cred,
          type: 'openid_credential',
          locations: [endpointMetadata.issuer],

          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore
          format: cred!.format,
        } satisfies AuthorizationDetails
      })
    if (!authorizationDetails || (Array.isArray(authorizationDetails) && authorizationDetails.length === 0)) {
      throw Error(`Could not create authorization details from credential offer. Please pass in explicit details`)
    }
  }
  if (!endpointMetadata?.authorization_endpoint) {
    throw Error('Server metadata does not contain authorization endpoint')
  }
  const parEndpoint = endpointMetadata.credentialIssuerMetadata?.pushed_authorization_request_endpoint

  // add 'openid' scope if not present
  if (!scope?.includes('openid')) {
    scope = ['openid', scope].filter((s) => !!s).join(' ')
  }

  let queryObj: { [key: string]: string } | PushedAuthorizationResponse = {
    response_type: ResponseType.AUTH_CODE,
    ...(!pkce.disabled && {
      code_challenge_method: pkce.codeChallengeMethod ?? CodeChallengeMethod.S256,
      code_challenge: pkce.codeChallenge,
    }),
    authorization_details: JSON.stringify(handleAuthorizationDetailsV1_0_11(endpointMetadata, authorizationDetails)),
    ...(redirectUri && { redirect_uri: redirectUri }),
    ...(clientId && { client_id: clientId }),
    ...(credentialOffer?.issuerState && { issuer_state: credentialOffer.issuerState }),
    scope,
  }

  if (!parEndpoint && parMode === PARMode.REQUIRE) {
    throw Error(`PAR mode is set to required by Authorization Server does not support PAR!`)
  } else if (parEndpoint && parMode !== PARMode.NEVER) {
    logger.debug(`USING PAR with endpoint ${parEndpoint}`)
    const parResponse = await formPost<PushedAuthorizationResponse>(
      parEndpoint,
      convertJsonToURI(queryObj, {
        mode: JsonURIMode.X_FORM_WWW_URLENCODED,
        uriTypeProperties: ['client_id', 'request_uri', 'redirect_uri', 'scope', 'authorization_details', 'issuer_state'],
      }),
      { contentType: 'application/x-www-form-urlencoded', accept: 'application/json' },
    )
    if (parResponse.errorBody || !parResponse.successBody) {
      console.log(JSON.stringify(parResponse.errorBody))
      console.log('Falling back to regular request URI, since PAR failed')
      if (parMode === PARMode.REQUIRE) {
        throw Error(`PAR error: ${parResponse.origResponse.statusText}`)
      }
    } else {
      logger.debug(`PAR response: ${JSON.stringify(parResponse.successBody, null, 2)}`)
      queryObj = { request_uri: parResponse.successBody.request_uri }
    }
  }
  await createSignedAuthRequestWhenNeeded(queryObj, { ...requestObjectOpts, aud: endpointMetadata.authorization_server })

  logger.debug(`Object that will become query params: ` + JSON.stringify(queryObj, null, 2))
  const url = convertJsonToURI(queryObj, {
    baseUrl: endpointMetadata.authorization_endpoint,
    uriTypeProperties: ['client_id', 'request_uri', 'redirect_uri', 'scope', 'authorization_details', 'issuer_state'],
    // arrayTypeProperties: ['authorization_details'],
    mode: JsonURIMode.X_FORM_WWW_URLENCODED,
    // We do not add the version here, as this always needs to be form encoded
  })
  logger.debug(`Authorization Request URL: ${url}`)
  return url
}

const handleAuthorizationDetailsV1_0_11 = (
  endpointMetadata: EndpointMetadataResultV1_0_11,
  authorizationDetails?: AuthorizationDetails | AuthorizationDetails[],
): AuthorizationDetails | AuthorizationDetails[] | undefined => {
  if (authorizationDetails) {
    if (typeof authorizationDetails === 'string') {
      // backwards compat for older versions of the lib
      return authorizationDetails
    }
    if (Array.isArray(authorizationDetails)) {
      return authorizationDetails
        .filter((value) => typeof value !== 'string')
        .map((value) => handleLocations(endpointMetadata, typeof value === 'string' ? value : { ...value }))
    } else {
      return handleLocations(endpointMetadata, { ...authorizationDetails })
    }
  }
  return authorizationDetails
}

const handleLocations = (endpointMetadata: EndpointMetadataResultV1_0_11, authorizationDetails: AuthorizationDetails) => {
  if (typeof authorizationDetails === 'string') {
    // backwards compat for older versions of the lib
    return authorizationDetails
  }
  if (authorizationDetails && (endpointMetadata.credentialIssuerMetadata?.authorization_server || endpointMetadata.authorization_endpoint)) {
    if (authorizationDetails.locations) {
      if (Array.isArray(authorizationDetails.locations)) {
        authorizationDetails.locations.push(endpointMetadata.issuer)
      } else {
        authorizationDetails.locations = [authorizationDetails.locations as string, endpointMetadata.issuer]
      }
    } else {
      authorizationDetails.locations = [endpointMetadata.issuer]
    }
  }
  return authorizationDetails
}
