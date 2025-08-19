import { HasherSync } from '@sphereon/ssi-types'
import {
  DcqlMdocCredential,
  DcqlPresentation,
  DcqlPresentationResult,
  DcqlQuery,
  DcqlSdJwtVcCredential,
  DcqlW3cVcCredential
} from 'dcql'
import { extractDataFromPath } from '../helpers'
import { extractDcqlPresentationFromDcqlVpToken, hasCryptographicHolderBinding } from './OpenID4VP'
import { AuthorizationRequestPayload } from '../types'

/**
 * Finds a valid DcqlQuery inside the given AuthenticationRequestPayload
 * throws exception if the DcqlQuery is not valid
 * returns the decoded dcql query if a valid instance found
 * @param authorizationRequestPayload object that can have a dcql_query inside
 * @param version
 */

export class Dcql {
  static findValidDcqlQuery = async (authorizationRequestPayload: AuthorizationRequestPayload): Promise<DcqlQuery | undefined> => {
    const dcqlQuery: string[] = extractDataFromPath(authorizationRequestPayload ?? {}, '$..dcql_query').map((d) => d.value)
//.claims?.vp_token
    if (dcqlQuery.length === 0) {
      return undefined
    }

    if (dcqlQuery.length > 1) {
      throw new Error('Found multiple dcql_query in vp_token. Only one is allowed')
    }

    return DcqlQuery.parse(JSON.parse(dcqlQuery[0]))
  }

  static getDcqlPresentationResult = (
    record: DcqlPresentation | string,
    dcqlQuery: DcqlQuery,
    opts: {
      hasher?: HasherSync
    },
  ) => {
    const dcqlPresentation = Object.fromEntries(
      Object.entries(extractDcqlPresentationFromDcqlVpToken(record, opts)).map(([queryId, p]) => {
        switch (p.format) {
          case 'mso_mdoc':
            return [queryId, {
                credential_format: p.format,
                doctype: p.vcs[0].credential.toJson().docType,
                namespaces: p.vcs[0].decoded,
                cryptographic_holder_binding: hasCryptographicHolderBinding(p.format, p.vcs[0])
              } satisfies DcqlMdocCredential
            ]
          case 'vc+sd-jwt':
            return [queryId, {
                credential_format: 'dc+sd-jwt',
                vct: p.vcs[0].decoded.vct,
                claims: p.vcs[0].decoded,
                cryptographic_holder_binding: hasCryptographicHolderBinding('dc+sd-jwt', p.vcs[0])
              } satisfies DcqlSdJwtVcCredential
            ]
          case 'jwt_vp':
            return [queryId, {
              credential_format: 'jwt_vc_json',
              claims: p.vcs[0].decoded,
              cryptographic_holder_binding: hasCryptographicHolderBinding('jwt_vc_json', p.vcs[0]),
              type: p.vcs[0].credential.type
            } satisfies DcqlW3cVcCredential
            ]
          case 'ldp_vp':
            return [queryId, {
              credential_format: 'ldp_vc',
              claims: p.vcs[0].decoded,
              cryptographic_holder_binding: hasCryptographicHolderBinding('ldp_vc', p.vcs[0]),
              type: p.vcs[0].credential.type
            } satisfies DcqlW3cVcCredential
            ]
          default:
            const format: string = (p as any).format;
            throw new Error(`Unknown DcqlPresentation format ${format}`)
        }

        // if (p.format === 'mso_mdoc') {
        //   return [
        //     queryId,
        //     {
        //       credential_format: 'mso_mdoc',
        //       doctype: p.vcs[0].credential.toJson().docType,
        //       namespaces: p.vcs[0].decoded,
        //       cryptographic_holder_binding: true, // TODO
        //     } satisfies DcqlMdocCredential,
        //   ]
        // } else if (p.format === 'dc+sd-jwt') {
        //   return [
        //     queryId,
        //     {
        //       credential_format: 'dc+sd-jwt',
        //       vct: p.vcs[0].decoded.vct,
        //       claims: p.vcs[0].decoded,
        //       cryptographic_holder_binding: true, // TODO
        //     } satisfies DcqlSdJwtVcCredential,
        //   ]
        // } else {
        //   throw new Error('DcqlPresentation atm only supports mso_mdoc and dc+sd-jwt')
        // }
      }),
    )

    return DcqlPresentationResult.fromDcqlPresentation(dcqlPresentation, { dcqlQuery })
  }

  static assertValidDcqlPresentationResult = async (
    record: DcqlPresentation | string,
    dcqlQuery: DcqlQuery,
    opts: {
      hasher?: HasherSync
    },
  ) => {
    const result = Dcql.getDcqlPresentationResult(record, dcqlQuery, opts)
    return DcqlPresentationResult.validate(result)
  }
}
