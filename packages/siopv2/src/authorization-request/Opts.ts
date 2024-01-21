import { assertValidRequestObjectOpts } from '../request-object/Opts';
import { ExternalVerification, InternalVerification, isExternalVerification, isInternalVerification, SIOPErrors } from '../types';

import { assertValidRequestRegistrationOpts } from './RequestRegistration';
import { CreateAuthorizationRequestOpts, VerifyAuthorizationRequestOpts } from './types';

export const assertValidVerifyAuthorizationRequestOpts = (opts: VerifyAuthorizationRequestOpts) => {
  if (!opts || !opts.verification || (!isExternalVerification(opts.verification) && !isInternalVerification(opts.verification))) {
    throw new Error(SIOPErrors.VERIFY_BAD_PARAMS);
  }
  if (!opts.correlationId) {
    throw new Error('No correlation id found');
  }
};

export const assertValidAuthorizationRequestOpts = (opts: CreateAuthorizationRequestOpts) => {
  if (!opts || !opts.requestObject || (!opts.payload && !opts.requestObject.payload) || (opts.payload?.request_uri && !opts.requestObject.payload)) {
    throw new Error(SIOPErrors.BAD_PARAMS);
  }
  assertValidRequestObjectOpts(opts.requestObject, false);
  assertValidRequestRegistrationOpts(opts['registration'] ? opts['registration'] : opts.clientMetadata);
};

export const mergeVerificationOpts = (
  classOpts: {
    verification?: InternalVerification | ExternalVerification;
  },
  requestOpts: {
    correlationId: string;
    verification?: InternalVerification | ExternalVerification;
  },
) => {
  const resolver = requestOpts.verification?.resolveOpts?.resolver ?? classOpts.verification?.resolveOpts?.resolver;
  const wellknownDIDVerifyCallback = requestOpts.verification?.wellknownDIDVerifyCallback ?? classOpts.verification?.wellknownDIDVerifyCallback;
  const presentationVerificationCallback =
    requestOpts.verification?.presentationVerificationCallback ?? classOpts.verification?.presentationVerificationCallback;
  const replayRegistry = requestOpts.verification?.replayRegistry ?? classOpts.verification?.replayRegistry;
  return {
    ...classOpts.verification,
    ...requestOpts.verification,
    ...(wellknownDIDVerifyCallback && { wellknownDIDVerifyCallback }),
    ...(presentationVerificationCallback && { presentationVerificationCallback }),
    ...(replayRegistry && { replayRegistry }),
    resolveOpts: {
      ...classOpts.verification?.resolveOpts,
      ...requestOpts.verification?.resolveOpts,
      ...(resolver && { resolver }),
      jwtVerifyOpts: {
        ...classOpts.verification?.resolveOpts?.jwtVerifyOpts,
        ...requestOpts.verification?.resolveOpts?.jwtVerifyOpts,
        ...(resolver && { resolver }),
        policies: {
          ...classOpts.verification?.resolveOpts?.jwtVerifyOpts?.policies,
          ...requestOpts.verification?.resolveOpts?.jwtVerifyOpts?.policies,
          aud: false, // todo: check why we are setting this. Probably needs a PR upstream in DID-JWT
        },
      },
    },
    revocationOpts: {
      ...classOpts.verification?.revocationOpts,
      ...requestOpts.verification?.revocationOpts,
      revocationVerificationCallback:
        requestOpts.verification?.revocationOpts?.revocationVerificationCallback ??
        classOpts?.verification?.revocationOpts?.revocationVerificationCallback,
    },
  };
};
