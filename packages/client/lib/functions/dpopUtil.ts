import { dpopTokenRequestNonceError } from '@sphereon/oid4vc-common'
import { OpenIDResponse } from '@sphereon/oid4vci-common'

export type RetryRequestWithDPoPNonce = { ok: true; dpopNonce: string } | { ok: false }

export function shouldRetryTokenRequestWithDPoPNonce(response: OpenIDResponse<unknown, unknown>): RetryRequestWithDPoPNonce {
  if (!response.errorBody || response.errorBody.error !== dpopTokenRequestNonceError) {
    return { ok: false }
  }

  const dPoPNonce = response.origResponse.headers.get('DPoP-Nonce')
  if (!dPoPNonce) {
    throw new Error('Missing required DPoP-Nonce header.')
  }

  return { ok: true, dpopNonce: dPoPNonce }
}

export function shouldRetryResourceRequestWithDPoPNonce(response: OpenIDResponse<unknown, unknown>): RetryRequestWithDPoPNonce {
  if (!response.errorBody || response.origResponse.status !== 401) {
    return { ok: false }
  }

  const wwwAuthenticateHeader = response.origResponse.headers.get('WWW-Authenticate')
  if (!wwwAuthenticateHeader?.includes(dpopTokenRequestNonceError)) {
    return { ok: false }
  }

  const dPoPNonce = response.origResponse.headers.get('DPoP-Nonce')
  if (!dPoPNonce) {
    throw new Error('Missing required DPoP-Nonce header.')
  }

  return { ok: true, dpopNonce: dPoPNonce }
}
