import { assertValidRequestObjectOpts } from '../request-object/Opts'
import { assertValidRequestRegistrationOpts } from './RequestRegistration'
import { ResponseMode, SIOPErrors, SupportedVersion, Verification } from '../types'
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

  // DC API response modes are only valid for OID4VP v1
  const responseMode = opts.payload?.response_mode ?? opts.requestObject?.payload?.response_mode
  if ((responseMode === ResponseMode.DC_API || responseMode === ResponseMode.DC_API_JWT) && opts.version === SupportedVersion.SIOPv2_OID4VP_D28) {
    throw new Error(`${SIOPErrors.INVALID_REQUEST}: dc_api response modes are only supported in OID4VP v1`)
  }
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
