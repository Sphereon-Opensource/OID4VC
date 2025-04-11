import { assertValidRequestObjectOpts } from '../request-object/Opts'
import { SIOPErrors, Verification } from '../types'

import { assertValidRequestRegistrationOpts } from './RequestRegistration'
import { CreateAuthorizationRequestOpts, VerifyAuthorizationRequestOpts } from './types'

export const assertValidVerifyAuthorizationRequestOpts = (opts: VerifyAuthorizationRequestOpts) => {
  if (!opts || !opts.verification || !opts.verifyJwtCallback) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS)
  }
  if (!opts.correlationId) {
    throw new Error('No correlation id found')
  }
}

export const assertValidAuthorizationRequestOpts = (opts: CreateAuthorizationRequestOpts) => {
  if (!opts || !opts.requestObject || (!opts.payload && !opts.requestObject.payload) || (opts.payload?.request_uri && !opts.requestObject.payload)) {
    throw new Error(SIOPErrors.BAD_PARAMS)
  }
  assertValidRequestObjectOpts(opts.requestObject, false)
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  assertValidRequestRegistrationOpts(opts['registration'] ?? opts.clientMetadata)
}

export const mergeVerificationOpts = (
  classOpts: {
    verification?: Verification
  },
  requestOpts: {
    correlationId: string
    verification?: Verification
  },
) => {
  const presentationVerificationCallback =
    requestOpts.verification?.presentationVerificationCallback ?? classOpts.verification?.presentationVerificationCallback
  const replayRegistry = requestOpts.verification?.replayRegistry ?? classOpts.verification?.replayRegistry
  return {
    ...classOpts.verification,
    ...requestOpts.verification,
    ...(presentationVerificationCallback && { presentationVerificationCallback }),
    ...(replayRegistry && { replayRegistry }),
    revocationOpts: {
      ...classOpts.verification?.revocationOpts,
      ...requestOpts.verification?.revocationOpts,
      revocationVerificationCallback:
        requestOpts.verification?.revocationOpts?.revocationVerificationCallback ??
        classOpts?.verification?.revocationOpts?.revocationVerificationCallback,
    },
  }
}
