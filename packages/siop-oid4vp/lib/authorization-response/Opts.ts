import { SIOPErrors } from '../types'

import { AuthorizationResponseOpts, VerifyAuthorizationResponseOpts } from './types'

export const assertValidResponseOpts = (opts: AuthorizationResponseOpts) => {
  if (!opts?.createJwtCallback) {
    throw new Error(SIOPErrors.BAD_PARAMS)
  }
}

export const assertValidVerifyOpts = (opts: VerifyAuthorizationResponseOpts) => {
  if (!opts?.verification || !opts.verifyJwtCallback) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS)
  }
}
