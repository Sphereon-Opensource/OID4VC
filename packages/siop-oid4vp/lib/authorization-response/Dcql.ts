import { Hasher } from '@sphereon/ssi-types'
import { DcqlMdocRepresentation, DcqlPresentationRecord, DcqlQuery, DcqlSdJwtVcRepresentation } from 'dcql'
import { DcqlPresentationQueryResult } from 'dcql'

import { extractDataFromPath } from '../helpers'
import { AuthorizationRequestPayload, SIOPErrors } from '../types'

import { extractPresentationRecordFromDcqlVpToken } from './OpenID4VP'

/**
 * Finds a valid DcqlQuery inside the given AuthenticationRequestPayload
 * throws exception if the DcqlQuery is not valid
 * returns the decoded dcql query if a valid instance found
 * @param authorizationRequestPayload object that can have a dcql_query inside
 * @param version
 */
export const findValidDcqlQuery = async (authorizationRequestPayload: AuthorizationRequestPayload): Promise<DcqlQuery | undefined> => {
  const dcqlQuery: string[] = extractDataFromPath(authorizationRequestPayload, '$.dcql_query').map((d) => d.value)
  const definitions = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition')
  const definitionsFromList = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition[*]')
  const definitionRefs = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition_uri')
  const definitionRefsFromList = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition_uri[*]')

  const hasPD = (definitions && definitions.length > 0) || (definitionsFromList && definitionsFromList.length > 0)
  const hasPdRef = (definitionRefs && definitionRefs.length > 0) || (definitionRefsFromList && definitionRefsFromList.length > 0)
  const hasDcql = dcqlQuery && dcqlQuery.length > 0

  if ([hasPD, hasPdRef, hasDcql].filter(Boolean).length > 1) {
    throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_NON_EXCLUSIVE)
  }

  if (dcqlQuery.length === 0) return undefined

  if (dcqlQuery.length > 1) {
    throw new Error('Found multiple dcql_query in vp_token. Only one is allowed')
  }

  return DcqlQuery.parse(JSON.parse(dcqlQuery[0]))
}

export const getDcqlPresentationResult = (record: DcqlPresentationRecord | string, dcqlQuery: DcqlQuery, opts: { hasher?: Hasher }) => {
  const wrappedPresentations = Object.values(extractPresentationRecordFromDcqlVpToken(record, opts))
  const credentials = wrappedPresentations.map((p) => {
    if (p.format === 'mso_mdoc') {
      return { docType: p.vcs[0].credential.toJson().docType, namespaces: p.vcs[0].decoded } satisfies DcqlMdocRepresentation
    } else if (p.format === 'vc+sd-jwt') {
      return { vct: p.vcs[0].decoded.vct, claims: p.vcs[0].decoded } satisfies DcqlSdJwtVcRepresentation
    } else {
      throw new Error('DcqlPresentation atm only supports mso_mdoc and vc+sd-jwt')
    }
  })

  return DcqlPresentationQueryResult.query(credentials, { dcqlQuery })
}

export const assertValidDcqlPresentationRecord = async (record: DcqlPresentationRecord | string, dcqlQuery: DcqlQuery, opts: { hasher?: Hasher }) => {
  const result = getDcqlPresentationResult(record, dcqlQuery, opts)
  return DcqlPresentationQueryResult.validate(result)
}
