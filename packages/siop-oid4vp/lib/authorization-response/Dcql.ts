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
          const credentials = p.vcs.map(vc => {
            switch (p.format) {
              case 'mso_mdoc':
                return {
                  credential_format: p.format,
                  doctype: vc.credential.toJson().docType,
                  namespaces: vc.decoded,
                  cryptographic_holder_binding: hasCryptographicHolderBinding(p.format, vc),
                } satisfies DcqlMdocCredential

              case 'vc+sd-jwt':
                return {
                  credential_format: 'dc+sd-jwt',
                  vct: vc.decoded.vct,
                  claims: vc.decoded,
                  cryptographic_holder_binding: hasCryptographicHolderBinding('dc+sd-jwt', vc),
                } satisfies DcqlSdJwtVcCredential

              case 'jwt_vp':
                return {
                  credential_format: 'jwt_vc_json',
                  claims: vc.decoded,
                  cryptographic_holder_binding: hasCryptographicHolderBinding('jwt_vc_json', vc),
                  type: vc.credential.type,
                } satisfies DcqlW3cVcCredential

              case 'ldp_vp':
                return {
                  credential_format: 'ldp_vc',
                  claims: vc.decoded,
                  cryptographic_holder_binding: hasCryptographicHolderBinding('ldp_vc', vc),
                  type: vc.credential.type,
                } satisfies DcqlW3cVcCredential

              default:
                const format: string = (p as any).format;
                throw new Error(`Unknown DcqlPresentation format ${format}`)
            }
          })

          return [queryId, credentials]
        })
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
