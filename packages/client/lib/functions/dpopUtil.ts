import { dpopResourceAuthenticateError, dpopTokenRequestNonceError } from '@sphereon/oid4vc-common';
import { OpenIDResponse } from 'oid4vci-common';

export function dPoPShouldRetryRequestWithNonce(response: OpenIDResponse<unknown, unknown>) {
  if (response.errorBody && response.errorBody.error === dpopTokenRequestNonceError) {
    const dPoPNonce = response.errorBody.headers.get('DPoP-Nonce');
    if (!dPoPNonce) {
      throw new Error('The DPoP nonce was not returned');
    }

    return { ok: true, dpopNonce: dPoPNonce } as const;
  }

  return { ok: false } as const;
}

export function dPoPShouldRetryResourceRequestWithNonce(response: OpenIDResponse<unknown, unknown>) {
  if (response.errorBody && response.origResponse.status === 401) {
    const wwwAuthenticateHeader = response.errorBody.headers?.get('WWW-Authenticate');
    if (!wwwAuthenticateHeader?.includes(dpopResourceAuthenticateError)) {
      return { ok: false } as const;
    }

    const dPoPNonce = response.errorBody.headers.get('DPoP-Nonce');
    if (!dPoPNonce) {
      throw new Error('The DPoP nonce was not returned');
    }

    return { ok: true, dpopNonce: dPoPNonce } as const;
  }

  return { ok: false } as const;
}
