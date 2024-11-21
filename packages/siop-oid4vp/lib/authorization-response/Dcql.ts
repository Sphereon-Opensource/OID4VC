import { DcqlQuery } from 'dcql'

import { extractDataFromPath } from '../helpers'
import { AuthorizationRequestPayload, SIOPErrors } from '../types'

/**
 * Finds a valid DcqlQuery inside the given AuthenticationRequestPayload
 * throws exception if the DcqlQuery is not valid
 * returns the decoded dcql query if a valid instance found
 * @param authorizationRequestPayload object that can have a dcql_query inside
 * @param version
 */
export const findValidDcqlQuery = async (authorizationRequestPayload: AuthorizationRequestPayload): Promise<DcqlQuery | undefined> => {
  const dcqlQuery: string[] = extractDataFromPath(authorizationRequestPayload, '$.dcql_query').map((d) => d.value)
  const dcqlQueryList: string[] = extractDataFromPath(authorizationRequestPayload, '$.dcql_query[*]').map((d) => d.value)
  const definitions = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition')
  const definitionsFromList = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition[*]')
  const definitionRefs = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition_uri')
  const definitionRefsFromList = extractDataFromPath(authorizationRequestPayload, '$.presentation_definition_uri[*]')

  const hasPD = (definitions && definitions.length > 0) || (definitionsFromList && definitionsFromList.length > 0)
  const hasPdRef = (definitionRefs && definitionRefs.length > 0) || (definitionRefsFromList && definitionRefsFromList.length > 0)
  const hasDcql = (dcqlQuery && dcqlQuery.length > 0) || (dcqlQueryList && dcqlQueryList.length > 0)

  if ([hasPD, hasPdRef, hasDcql].filter(Boolean).length > 1) {
    throw new Error(SIOPErrors.REQUEST_CLAIMS_PRESENTATION_NON_EXCLUSIVE)
  }

  if (dcqlQuery.length > 1 || dcqlQueryList.length > 1) {
    throw new Error('Found multiple dcql_query in vp_token. Only one is allowed')
  }

  const encoded = dcqlQuery.length ? dcqlQuery[0] : dcqlQueryList[0]
  if (!encoded) return undefined

  const parsedDcqlQuery = DcqlQuery.parse(JSON.parse(encoded))
  DcqlQuery.validate(parsedDcqlQuery)

  return parsedDcqlQuery
}
