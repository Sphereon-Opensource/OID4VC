import { calculateJwkThumbprint, JWK, uuidv4 } from '@sphereon/oid4vc-common'
import {
  AccessTokenRequest,
  AccessTokenResponse,
  Alg,
  CNonceState,
  CredentialOfferSession,
  EXPIRED_PRE_AUTHORIZED_CODE,
  GrantTypes,
  INVALID_PRE_AUTHORIZED_CODE,
  IssueStatus,
  IStateManager,
  Jwt,
  JWTSignerCallback,
  JWTVerifyCallback,
  PIN_NOT_MATCH_ERROR,
  PIN_VALIDATION_ERROR,
  PRE_AUTH_CODE_LITERAL,
  PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
  TokenError,
  TokenErrorResponse,
  UNSUPPORTED_GRANT_TYPE_ERROR,
  USER_PIN_NOT_REQUIRED_ERROR,
  USER_PIN_REQUIRED_ERROR,
  USER_PIN_TX_CODE_SPEC_ERROR,
} from '@sphereon/oid4vci-common'

import { isPreAuthorizedCodeExpired } from '../functions'

export interface ITokenEndpointOpts {
  tokenEndpointDisabled?: boolean // Disable if used in an existing OAuth2/OIDC environment and have the AS handle tokens
  tokenPath?: string // token path can either be defined here, or will be deduced from issuer metadata
  interval?: number
  cNonceExpiresIn?: number
  tokenExpiresIn?: number
  preAuthorizedCodeExpirationDuration?: number
  accessTokenSignerCallback?: JWTSignerCallback
  accessTokenVerificationCallback?: JWTVerifyCallback<never>
  accessTokenIssuer?: string
  accessTokenProvider?: AccessTokenProvider
}

export type AccessTokenProvider = 'internal' | 'oidc' | 'oauth2'

export const generateAccessToken = async (
  opts: Required<Pick<ITokenEndpointOpts, 'accessTokenSignerCallback' | 'tokenExpiresIn' | 'accessTokenIssuer' | 'accessTokenProvider'>> & {
    additionalClaims?: Record<string, unknown>
    preAuthorizedCode?: string
    alg?: Alg
    dPoPJwk?: JWK
  },
): Promise<string> => {
  const {
    dPoPJwk,
    accessTokenIssuer,
    alg,
    accessTokenSignerCallback,
    tokenExpiresIn,
    preAuthorizedCode,
    additionalClaims,
    accessTokenProvider = 'internal',
  } = opts
  // JWT uses seconds for iat and exp
  if (accessTokenProvider !== 'internal') {
    throw new TokenError(
      400,
      TokenErrorResponse.invalid_request,
      `Access token provider ${accessTokenProvider} is an external access token provider. We cannot generate tokens ourselves in this case`,
    )
  }
  const iat = new Date().getTime() / 1000
  const exp = iat + tokenExpiresIn
  const cnf = dPoPJwk ? { cnf: { jkt: await calculateJwkThumbprint(dPoPJwk, 'sha256') } } : undefined
  const jwt: Jwt = {
    header: { typ: 'JWT', alg: alg ?? Alg.ES256 },
    payload: {
      iat,
      exp,
      iss: accessTokenIssuer,
      ...cnf,
      ...(preAuthorizedCode && { preAuthorizedCode }),
      // Protected resources simultaneously supporting both the DPoP and Bearer schemes need to update how the
      // evaluation process is performed for bearer tokens to prevent downgraded usage of a DPoP-bound access token.
      // Specifically, such a protected resource MUST reject a DPoP-bound access token received as a bearer token per [RFC6750].
      token_type: dPoPJwk ? 'DPoP' : 'Bearer',
      ...additionalClaims,
    },
  }
  return await accessTokenSignerCallback(jwt)
}

export const isValidGrant = (assertedState: CredentialOfferSession, grantType: string): boolean => {
  if (assertedState.credentialOffer?.credential_offer?.grants) {
    // TODO implement authorization_code
    return (
      Object.keys(assertedState.credentialOffer?.credential_offer?.grants).includes(GrantTypes.PRE_AUTHORIZED_CODE) &&
      grantType === GrantTypes.PRE_AUTHORIZED_CODE
    )
  }
  return false
}

export const assertValidAccessTokenRequest = async (
  request: AccessTokenRequest,
  opts: {
    credentialOfferSessions: IStateManager<CredentialOfferSession>
    expirationDuration: number
  },
) => {
  const { credentialOfferSessions, expirationDuration } = opts
  // Only pre-auth supported for now
  if (request.grant_type !== GrantTypes.PRE_AUTHORIZED_CODE) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, UNSUPPORTED_GRANT_TYPE_ERROR)
  }

  // Pre-auth flow
  if (!request[PRE_AUTH_CODE_LITERAL]) {
    throw new TokenError(400, TokenErrorResponse.invalid_request, PRE_AUTHORIZED_CODE_REQUIRED_ERROR)
  }

  const credentialOfferSession = await credentialOfferSessions.getAsserted(request[PRE_AUTH_CODE_LITERAL])
  credentialOfferSession.status = IssueStatus.ACCESS_TOKEN_REQUESTED
  credentialOfferSession.lastUpdatedAt = +new Date()
  await credentialOfferSessions.set(request[PRE_AUTH_CODE_LITERAL], credentialOfferSession)
  if (!isValidGrant(credentialOfferSession, request.grant_type)) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, UNSUPPORTED_GRANT_TYPE_ERROR)
  }

  /*
 invalid_request:
 the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN
  */
  if (
    !credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.tx_code &&
    request.tx_code &&
    !request.user_pin
  ) {
    // >= v13
    throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_NOT_REQUIRED_ERROR)
  } else if (
    !credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.user_pin_required &&
    request.user_pin &&
    !request.tx_code
  ) {
    // <= v12
    throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_NOT_REQUIRED_ERROR)
  }
  /*
  invalid_request:
  the Authorization Server expects a PIN in the pre-authorized flow but the client does not provide a PIN
   */
  if (
    // >= v13
    !!credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.tx_code &&
    !request.tx_code
  ) {
    if (request.user_pin) {
      throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_TX_CODE_SPEC_ERROR)
    }
    throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_REQUIRED_ERROR)
  } else if (
    // <= v12
    credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.user_pin_required &&
    !credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.tx_code &&
    !request.user_pin
  ) {
    if (request.tx_code) {
      throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_TX_CODE_SPEC_ERROR)
    }
    throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_REQUIRED_ERROR)
  }

  if (isPreAuthorizedCodeExpired(credentialOfferSession, expirationDuration)) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, EXPIRED_PRE_AUTHORIZED_CODE)
  } else if (
    request[PRE_AUTH_CODE_LITERAL] !==
    credentialOfferSession.credentialOffer?.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.[PRE_AUTH_CODE_LITERAL]
  ) {
    throw new TokenError(400, TokenErrorResponse.invalid_grant, INVALID_PRE_AUTHORIZED_CODE)
  }
  /*
  invalid_grant:
  the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN
  the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
   */
  if (request.tx_code) {
    const txCodeOffer = credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.tx_code
    if (!txCodeOffer) {
      throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_NOT_REQUIRED_ERROR)
    } else if (txCodeOffer.input_mode === 'text') {
      if (!RegExp(`[\\D]{${txCodeOffer.length}`).test(request.tx_code)) {
        throw new TokenError(400, TokenErrorResponse.invalid_grant, `${PIN_VALIDATION_ERROR} ${txCodeOffer.length}`)
      }
    } else {
      if (!RegExp(`[\\d]{${txCodeOffer.length}}`).test(request.tx_code)) {
        throw new TokenError(400, TokenErrorResponse.invalid_grant, `${PIN_VALIDATION_ERROR} ${txCodeOffer.length}`)
      }
    }
    if (request.tx_code !== credentialOfferSession.txCode) {
      throw new TokenError(400, TokenErrorResponse.invalid_grant, PIN_NOT_MATCH_ERROR)
    }
  } else if (request.user_pin) {
    if (!/[\\d]{1,8}/.test(request.user_pin)) {
      throw new TokenError(400, TokenErrorResponse.invalid_grant, `${PIN_VALIDATION_ERROR} 1-8`)
    } else if (request.user_pin !== credentialOfferSession.txCode) {
      throw new TokenError(400, TokenErrorResponse.invalid_grant, PIN_NOT_MATCH_ERROR)
    }
  }

  return { preAuthSession: credentialOfferSession }
}

export const createAccessTokenResponse = async (
  request: AccessTokenRequest,
  opts: {
    credentialOfferSessions: IStateManager<CredentialOfferSession>
    cNonces: IStateManager<CNonceState>
    cNonce?: string
    cNonceExpiresIn?: number // expiration in seconds
    tokenExpiresIn: number // expiration in seconds
    // preAuthorizedCodeExpirationDuration?: number
    accessTokenSignerCallback: JWTSignerCallback
    accessTokenIssuer: string
    accessTokenProvider?: AccessTokenProvider
    interval?: number
    dPoPJwk?: JWK
  },
) => {
  const {
    dPoPJwk,
    credentialOfferSessions,
    cNonces,
    cNonceExpiresIn,
    tokenExpiresIn,
    accessTokenIssuer,
    accessTokenSignerCallback,
    interval,
    accessTokenProvider = 'internal',
  } = opts
  // Pre-auth flow
  const preAuthorizedCode = request[PRE_AUTH_CODE_LITERAL] as string

  const cNonce = opts.cNonce ?? uuidv4()
  await cNonces.set(cNonce, { cNonce, createdAt: +new Date(), preAuthorizedCode })

  const access_token = await generateAccessToken({
    tokenExpiresIn,
    accessTokenSignerCallback,
    preAuthorizedCode,
    accessTokenIssuer,
    dPoPJwk,
    accessTokenProvider,
  })

  const response: AccessTokenResponse = {
    access_token,
    token_type: dPoPJwk ? 'DPoP' : 'bearer',
    expires_in: tokenExpiresIn,
    c_nonce: cNonce,
    c_nonce_expires_in: cNonceExpiresIn,
    interval,
  }
  const credentialOfferSession = await credentialOfferSessions.getAsserted(preAuthorizedCode)
  credentialOfferSession.status = IssueStatus.ACCESS_TOKEN_CREATED
  credentialOfferSession.lastUpdatedAt = +new Date()
  await credentialOfferSessions.set(preAuthorizedCode, credentialOfferSession)
  return response
}
