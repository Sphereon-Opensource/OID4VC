import { defaultHasher } from '@sphereon/oid4vc-common'

import { VerifyAuthorizationRequestOpts } from '../authorization-request'
import { AuthorizationResponseOpts } from '../authorization-response'
import { LanguageTagUtils } from '../helpers'
import { AuthorizationResponseOptsSchema } from '../schemas'
import { PassBy, ResponseRegistrationOpts } from '../types'

import { OPBuilder } from './OPBuilder'

export const createResponseOptsFromBuilderOrExistingOpts = (opts: {
  builder?: OPBuilder
  responseOpts?: AuthorizationResponseOpts
}): AuthorizationResponseOpts => {
  let responseOpts: AuthorizationResponseOpts
  if (opts.builder) {
    responseOpts = {
      registration: {
        issuer: opts.builder.issuer,
        ...(opts.builder.responseRegistration as ResponseRegistrationOpts),
      },
      expiresIn: opts.builder.expiresIn,
      jwtIssuer: responseOpts?.jwtIssuer,
      createJwtCallback: opts.builder.createJwtCallback,
      encryptJwtCallback: opts.builder.encryptJwtCallback,
      responseMode: opts.builder.responseMode,
      ...(responseOpts?.version
        ? { version: responseOpts.version }
        : Array.isArray(opts.builder.supportedVersions) && opts.builder.supportedVersions.length > 0
          ? { version: opts.builder.supportedVersions[0] }
          : {}),
    }

    if (!responseOpts.registration.passBy) {
      responseOpts.registration.passBy = PassBy.VALUE
    }
    const languageTagEnabledFieldsNames = ['clientName', 'clientPurpose']
    const languageTaggedFields: Map<string, string> = LanguageTagUtils.getLanguageTaggedProperties(
      opts.builder.responseRegistration,
      languageTagEnabledFieldsNames,
    )

    languageTaggedFields.forEach((value: string, key: string) => {
      responseOpts.registration[key] = value
    })
  } else {
    responseOpts = {
      ...opts.responseOpts,
    }
  }

  const valid = AuthorizationResponseOptsSchema(responseOpts)
  if (!valid) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    //@ts-ignore
    throw new Error('OP builder validation error: ' + JSON.stringify(AuthorizationResponseOptsSchema.errors))
  }

  return responseOpts
}

export const createVerifyRequestOptsFromBuilderOrExistingOpts = (opts: {
  builder?: OPBuilder
  verifyOpts?: VerifyAuthorizationRequestOpts
}): VerifyAuthorizationRequestOpts => {
  return opts.builder
    ? {
        verifyJwtCallback: opts.builder.verifyJwtCallback,
        hasher: opts.builder.hasher ?? defaultHasher,
        verification: {},
        supportedVersions: opts.builder.supportedVersions,
        correlationId: undefined,
      }
    : opts.verifyOpts
}
