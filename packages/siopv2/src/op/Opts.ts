import { Resolvable } from 'did-resolver';

import { VerifyAuthorizationRequestOpts } from '../authorization-request';
import { AuthorizationResponseOpts } from '../authorization-response';
import { getResolverUnion, mergeAllDidMethods } from '../did';
import { LanguageTagUtils } from '../helpers';
import { AuthorizationResponseOptsSchema } from '../schemas';
import { InternalVerification, PassBy, ResponseRegistrationOpts, VerificationMode } from '../types';

import { OPBuilder } from './OPBuilder';

export const createResponseOptsFromBuilderOrExistingOpts = (opts: {
  builder?: OPBuilder;
  responseOpts?: AuthorizationResponseOpts;
}): AuthorizationResponseOpts => {
  if (opts?.builder?.resolvers.size && opts.builder?.responseRegistration?.subject_syntax_types_supported) {
    opts.builder.responseRegistration.subject_syntax_types_supported = mergeAllDidMethods(
      opts.builder.responseRegistration.subject_syntax_types_supported,
      opts.builder.resolvers,
    );
  }

  let responseOpts: AuthorizationResponseOpts;
  if (opts.builder) {
    responseOpts = {
      registration: {
        issuer: opts.builder.issuer,
        ...(opts.builder.responseRegistration as ResponseRegistrationOpts),
      },
      expiresIn: opts.builder.expiresIn,
      signature: opts.builder.signature,
      responseMode: opts.builder.responseMode,
      ...(responseOpts?.version
        ? { version: responseOpts.version }
        : Array.isArray(opts.builder.supportedVersions) && opts.builder.supportedVersions.length > 0
          ? { version: opts.builder.supportedVersions[0] }
          : {}),
    };

    if (!responseOpts.registration.passBy) {
      responseOpts.registration.passBy = PassBy.VALUE;
    }
    const languageTagEnabledFieldsNames = ['clientName', 'clientPurpose'];
    const languageTaggedFields: Map<string, string> = LanguageTagUtils.getLanguageTaggedProperties(
      opts.builder.responseRegistration,
      languageTagEnabledFieldsNames,
    );

    languageTaggedFields.forEach((value: string, key: string) => {
      responseOpts.registration[key] = value;
    });
  } else {
    responseOpts = {
      ...opts.responseOpts,
    };
  }

  const valid = AuthorizationResponseOptsSchema(responseOpts);
  if (!valid) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    //@ts-ignore
    throw new Error('OP builder validation error: ' + JSON.stringify(AuthorizationResponseOptsSchema.errors));
  }

  return responseOpts;
};

export const createVerifyRequestOptsFromBuilderOrExistingOpts = (opts: {
  builder?: OPBuilder;
  verifyOpts?: VerifyAuthorizationRequestOpts;
}): VerifyAuthorizationRequestOpts => {
  if (opts?.builder?.resolvers.size && opts.builder?.responseRegistration) {
    opts.builder.responseRegistration.subject_syntax_types_supported = mergeAllDidMethods(
      opts.builder.responseRegistration.subject_syntax_types_supported,
      opts.builder.resolvers,
    );
  }
  let resolver: Resolvable;
  if (opts.builder) {
    resolver = getResolverUnion(
      opts.builder.customResolver,
      opts.builder.responseRegistration.subject_syntax_types_supported,
      opts.builder.resolvers,
    );
  }
  return opts.builder
    ? {
        hasher: opts.builder.hasher,
        verification: {
          mode: VerificationMode.INTERNAL,
          checkLinkedDomain: opts.builder.checkLinkedDomain,
          wellknownDIDVerifyCallback: opts.builder.wellknownDIDVerifyCallback,
          resolveOpts: {
            subjectSyntaxTypesSupported: opts.builder.responseRegistration.subject_syntax_types_supported,
            resolver: resolver,
          },
        } as InternalVerification,
        supportedVersions: opts.builder.supportedVersions,
        correlationId: undefined,
      }
    : opts.verifyOpts;
};
