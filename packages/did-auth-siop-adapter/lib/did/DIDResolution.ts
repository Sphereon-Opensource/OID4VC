import { SubjectIdentifierType, SubjectSyntaxTypesSupportedValues } from '@sphereon/did-auth-siop'
import { getUniResolver, UniResolver } from '@sphereon/did-uni-client'
import { DIDResolutionOptions, DIDResolutionResult, ParsedDID, Resolvable, Resolver } from 'did-resolver'

import { DIDDocument, ResolveOpts } from '../types'

import { getMethodFromDid, toSIOPRegistrationDidMethod } from './index'

export function getResolver(opts: ResolveOpts): Resolvable {
  if (opts && typeof opts.resolver === 'object') {
    return opts.resolver
  }
  if (!opts || !opts.subjectSyntaxTypesSupported) {
    if (opts?.noUniversalResolverFallback) {
      throw Error(`No subject syntax types nor did methods configured for DID resolution, but fallback to universal resolver has been disabled`)
    }
    console.log(
      `Falling back to universal resolver as no resolve opts have been provided, or no subject syntax types supported are provided. It is wise to fix this`,
    )
    return new UniResolver()
  }

  const uniResolvers: {
    [p: string]: (did: string, _parsed: ParsedDID, _didResolver: Resolvable, _options: DIDResolutionOptions) => Promise<DIDResolutionResult>
  }[] = []
  if (opts.subjectSyntaxTypesSupported.indexOf(SubjectIdentifierType.DID) === -1) {
    const specificDidMethods = opts.subjectSyntaxTypesSupported.filter((sst) => sst.includes('did:'))
    if (!specificDidMethods.length) {
      throw new Error('No did method found.')
    }
    for (const didMethod of specificDidMethods) {
      const uniResolver = getUniResolver(getMethodFromDid(didMethod), { resolveUrl: opts.resolveUrl })
      uniResolvers.push(uniResolver)
    }
    return new Resolver(...uniResolvers)
  } else {
    if (opts?.noUniversalResolverFallback) {
      throw Error(`No subject syntax types nor did methods configured for DID resolution, but fallback to universal resolver has been disabled`)
    }
    console.log(
      `Falling back to universal resolver as no resolve opts have been provided, or no subject syntax types supported are provided. It is wise to fix this`,
    )
    return new UniResolver()
  }
}

/**
 * This method returns a resolver object in OP/RP
 * If the user of this library, configures OP/RP to have a customResolver, we will use that
 * If the user of this library configures OP/RP to use a custom resolver for any specific did method, we will use that
 * and in the end for the rest of the did methods, configured either with calling `addDidMethod` upon building OP/RP
 * (without any resolver configuration) or declaring in the subject_syntax_types_supported of the registration object
 * we will use universal resolver from Sphereon's DID Universal Resolver library
 * @param customResolver
 * @param subjectSyntaxTypesSupported
 * @param resolverMap
 */
export function getResolverUnion(
  customResolver: Resolvable,
  subjectSyntaxTypesSupported: string[] | string,
  resolverMap: Map<string, Resolvable>,
): Resolvable {
  if (customResolver) {
    return customResolver
  }
  const fallbackResolver: Resolvable = customResolver ? customResolver : new UniResolver()
  const uniResolvers: {
    [p: string]: (did: string, _parsed: ParsedDID, _didResolver: Resolvable, _options: DIDResolutionOptions) => Promise<DIDResolutionResult>
  }[] = []
  const subjectTypes: string[] = []
  if (subjectSyntaxTypesSupported) {
    typeof subjectSyntaxTypesSupported === 'string'
      ? subjectTypes.push(subjectSyntaxTypesSupported)
      : subjectTypes.push(...subjectSyntaxTypesSupported)
  }
  if (subjectTypes.indexOf(SubjectSyntaxTypesSupportedValues.DID.valueOf()) !== -1) {
    return customResolver ? customResolver : new UniResolver()
  }
  const specificDidMethods = subjectTypes.filter((sst) => !!sst && sst.startsWith('did:'))
  specificDidMethods.forEach((dm) => {
    let methodResolver
    if (!resolverMap.has(dm) || resolverMap.get(dm) === null) {
      methodResolver = getUniResolver(getMethodFromDid(dm))
    } else {
      methodResolver = resolverMap.get(dm)
    }
    uniResolvers.push(methodResolver)
  })
  return subjectTypes.indexOf(SubjectSyntaxTypesSupportedValues.DID.valueOf()) !== -1
    ? new Resolver(...{ fallbackResolver, ...uniResolvers })
    : new Resolver(...uniResolvers)
}

export function mergeAllDidMethods(subjectSyntaxTypesSupported: string | string[], resolvers: Map<string, Resolvable>): string[] {
  if (!Array.isArray(subjectSyntaxTypesSupported)) {
    subjectSyntaxTypesSupported = [subjectSyntaxTypesSupported]
  }
  const unionSubjectSyntaxTypes = new Set()
  subjectSyntaxTypesSupported.forEach((sst) => unionSubjectSyntaxTypes.add(sst))
  resolvers.forEach((_, didMethod) => unionSubjectSyntaxTypes.add(toSIOPRegistrationDidMethod(didMethod)))
  return Array.from(unionSubjectSyntaxTypes) as string[]
}

export async function resolveDidDocument(did: string, opts?: ResolveOpts): Promise<DIDDocument> {
  // todo: The accept is only there because did:key used by Veramo requires it. According to the spec it is optional. It should not hurt, but let's test
  const result = await getResolver({ ...opts }).resolve(did, { accept: 'application/did+ld+json' })
  if (result?.didResolutionMetadata?.error) {
    throw Error(result.didResolutionMetadata.error)
  }
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  if (!result.didDocument && result.id) {
    // todo: This looks like a bug. It seems that sometimes we get back a DID document directly instead of a did resolution results
    return result as unknown as DIDDocument
  }
  return result.didDocument
}
