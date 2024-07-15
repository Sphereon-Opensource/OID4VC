import { CreateAuthorizationRequestOpts, PropertyTarget, PropertyTargets, RequestPropertyWithTargets } from '../authorization-request'
import { VerifyAuthorizationResponseOpts } from '../authorization-response'
// import { CreateAuthorizationRequestOptsSchema } from '../schemas';
import { ClientMetadataOpts, RequestObjectPayload, SIOPErrors, Verification } from '../types'

import { RPBuilder } from './RPBuilder'

export const createRequestOptsFromBuilderOrExistingOpts = (opts: { builder?: RPBuilder; createRequestOpts?: CreateAuthorizationRequestOpts }) => {
  const version = opts.builder ? opts.builder.getSupportedRequestVersion() : opts.createRequestOpts.version
  if (!version) {
    throw Error(SIOPErrors.NO_REQUEST_VERSION)
  }

  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const createRequestOpts: CreateAuthorizationRequestOpts = opts.builder
    ? {
        version,
        payload: {
          ...opts.builder.authorizationRequestPayload,
          // ...(isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, opts.builder.requestObjectBy.targets) ? {passBy: opts.builder.requestObjectBy.passBy, request_uri: opts.buigfdlder.requestObjectBy.referenceUri}: {})
          //response_types_supported: opts.builder.clientMetadata?.responseTypesSupported,
          // subject_types_supported: opts.builder.clientMetadata?.subjectTypesSupported,
          // request_object_signing_alg_values_supported: opts.builder.clientMetadata?.requestObjectSigningAlgValuesSupported
          //scopes_supported: opts.builder.clientMetadata?.scopesSupported,
        },
        requestObject: {
          ...opts.builder.requestObjectBy,
          payload: {
            ...(opts.builder.requestObjectPayload as RequestObjectPayload),
            subject_types_supported: opts.builder.clientMetadata?.subjectTypesSupported,
            request_object_signing_alg_values_supported: opts.builder.clientMetadata?.requestObjectSigningAlgValuesSupported,
          },
          createJwtCallback: opts.builder.createJwtCallback,
        },
        clientMetadata: opts.builder.clientMetadata as ClientMetadataOpts,
      }
    : opts.createRequestOpts

  /*const valid = true; // fixme: re-enable schema: CreateAuthorizationRequestOptsSchema(createRequestOpts);
  if (!valid) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    //@ts-ignore
    throw new Error('RP builder validation error: ' + JSON.stringify(CreateAuthorizationRequestOptsSchema.errors));
  }*/
  return createRequestOpts
}

export const createVerifyResponseOptsFromBuilderOrExistingOpts = (opts: { builder?: RPBuilder; verifyOpts?: VerifyAuthorizationResponseOpts }) => {
  return opts.builder
    ? {
        hasher: opts.builder.hasher,
        verifyJwtCallback: opts.builder.verifyJwtCallback,
        verification: {
          presentationVerificationCallback: opts.builder.presentationVerificationCallback,
          supportedVersions: opts.builder.supportedVersions,
          revocationOpts: {
            revocationVerification: opts.builder.revocationVerification,
            revocationVerificationCallback: opts.builder.revocationVerificationCallback,
          },
          replayRegistry: opts.builder.sessionManager,
        } as Verification,
        audience: opts.builder.clientId || opts.builder.clientMetadata?.client_id,
      }
    : opts.verifyOpts
}

export const isTargetOrNoTargets = (searchTarget: PropertyTarget, targets?: PropertyTargets): boolean => {
  if (!targets) {
    return true
  }
  return isTarget(searchTarget, targets)
}

export const isTarget = (searchTarget: PropertyTarget, targets: PropertyTargets): boolean => {
  return Array.isArray(targets) ? targets.includes(searchTarget) : targets === searchTarget
}

export const assignIfAuth = <T>(opt: RequestPropertyWithTargets<T>, isDefaultTarget?: boolean): T => {
  if (
    isDefaultTarget
      ? isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, opt.targets)
      : isTarget(PropertyTarget.AUTHORIZATION_REQUEST, opt.targets)
  ) {
    return opt.propertyValue
  }
  return undefined
}

export const assignIfRequestObject = <T>(opt: RequestPropertyWithTargets<T>, isDefaultTarget?: boolean): T => {
  if (isDefaultTarget ? isTargetOrNoTargets(PropertyTarget.REQUEST_OBJECT, opt.targets) : isTarget(PropertyTarget.REQUEST_OBJECT, opt.targets)) {
    return opt.propertyValue
  }
  return undefined
}
