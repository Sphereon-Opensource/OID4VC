import {
  decodeSdJwtVc,
  getMdocDecodedPayload,
  HasherSync,
  IVerifiableCredential,
  JwtDecodedVerifiableCredential,
  MdocDocument,
  SdJwtDecodedVerifiableCredential,
} from '@sphereon/ssi-types'
import {
  DcqlMdocCredential,
  DcqlPresentation,
  DcqlPresentationResult,
  DcqlQuery,
  DcqlSdJwtVcCredential,
  DcqlW3cVcCredential
} from 'dcql'
import {extractDataFromPath} from '../helpers'
import {extractDcqlPresentationFromDcqlVpToken, hasCryptographicHolderBinding} from './OpenID4VP'
import {AuthorizationRequestPayload, Json, SupportedVersion} from '../types'

/**
 * Finds a valid DcqlQuery inside the given AuthenticationRequestPayload
 * throws exception if the DcqlQuery is not valid
 * returns the decoded dcql query if a valid instance found
 * @param authorizationRequestPayload object that can have a dcql_query inside
 * @param version
 */

export class Dcql {
  static findValidDcqlQuery = async (authorizationRequestPayload: AuthorizationRequestPayload, version?: SupportedVersion): Promise<DcqlQuery | undefined> => {
    const dcqlQuery: DcqlQuery.Input[] = extractDataFromPath(authorizationRequestPayload ?? {}, '$..dcql_query').map((d) => d.value)

    if (dcqlQuery.length === 0) {
      return undefined
    }

    if (dcqlQuery.length > 1) {
      throw new Error('Found multiple dcql_query in vp_token. Only one is allowed')
    }

    const parsedDcqlQuery = DcqlQuery.parse(dcqlQuery[0])

    if (version === SupportedVersion.OID4VP_v1) {
      const hasMeta = parsedDcqlQuery.credentials
          .filter(q => q.format === 'jwt_vc_json' || q.format === 'ldp_vc')
          .every(q => q.meta !== undefined)

      if (!hasMeta) {
        throw new Error('Missing meta property in DCQL query')
      }
    }

    return parsedDcqlQuery
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
                return Dcql.toDcqlMdocCredential(vc.original)
              case 'vc+sd-jwt': {
                const decoded = typeof vc.original === 'string' ? decodeSdJwtVc(vc.original, opts.hasher) : vc.original
                return Dcql.toDcqlSdJwtCredential(decoded)
              }
              case 'jwt_vp':
                return Dcql.toDcqlJwtCredential(vc.original)
              case 'ldp_vp':
                return Dcql.toDcqlJsonLdCredential(vc.original)
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

  static toDcqlMdocCredential = (vc: MdocDocument): DcqlMdocCredential => {
    return {
      credential_format: 'mso_mdoc',
      doctype: vc.toJson().docType,
      namespaces: getMdocDecodedPayload(vc),
      cryptographic_holder_binding: hasCryptographicHolderBinding('mso_mdoc', vc),
    } satisfies DcqlMdocCredential
  }

  static toDcqlSdJwtCredential = (vc: SdJwtDecodedVerifiableCredential): DcqlSdJwtVcCredential => {
    return {
      credential_format: 'dc+sd-jwt',
      vct: vc.decodedPayload.vct,
      claims: vc.decodedPayload,
      cryptographic_holder_binding: hasCryptographicHolderBinding('dc+sd-jwt', vc),
    } satisfies DcqlSdJwtVcCredential
  }

  static toDcqlJwtCredential = (vc: JwtDecodedVerifiableCredential): DcqlW3cVcCredential => {
    return {
      credential_format: 'jwt_vc_json',
      claims: vc.vc.credentialSubject as { [x: string]: Json },
      cryptographic_holder_binding: hasCryptographicHolderBinding('jwt_vc_json', vc),
      type: vc.vc.type,
    } satisfies DcqlW3cVcCredential
  }

  static toDcqlJsonLdCredential = (vc: IVerifiableCredential): DcqlW3cVcCredential => {
    return {
      credential_format: 'ldp_vc',
      claims: vc.credentialSubject as { [x: string]: Json },
      cryptographic_holder_binding: hasCryptographicHolderBinding('ldp_vc', vc),
      type: vc.type,
    } satisfies DcqlW3cVcCredential
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
