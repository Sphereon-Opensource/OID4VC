import { getNonce, removeNullUndefined } from '../helpers'
import { RequestObject } from '../request-object'
import { isTarget, isTargetOrNoTargets } from '../rp/Opts'
import { RPRegistrationMetadataPayloadSchema } from '../schemas'
import { createRequestRegistration } from './RequestRegistration'
import { ClaimPayloadOpts, CreateAuthorizationRequestOpts, PropertyTarget } from './types'
import { AuthorizationRequestPayload, ClaimPayload, ClientMetadataOpts, PassBy, RPRegistrationMetadataPayload, SIOPErrors } from '../types'

export const createClaimsProperties = async (opts: ClaimPayloadOpts): Promise<ClaimPayload | undefined> => {
  if (!opts || !opts.vp_token) {
    return undefined
  }

  return {
    ...(opts.id_token && { id_token: opts.id_token }),
    vp_token: { dcql_query: opts.vp_token.dcql_query },
  }
}

export const createAuthorizationRequestPayload = async (
  opts: CreateAuthorizationRequestOpts,
  requestObject?: RequestObject,
): Promise<AuthorizationRequestPayload> => {
  const payload = opts.payload
  const state = payload?.state ?? undefined
  const nonce = payload?.nonce ? getNonce(state ?? payload.nonce, payload.nonce) : undefined
  // TODO: if opts['registration] throw Error to get rid of test code using that key
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const clientMetadata = opts['registration'] ?? (opts.clientMetadata as ClientMetadataOpts)
  const registration = await createRequestRegistration(clientMetadata, opts)

  const claims = opts.payload?.claims
  const isRequestTarget = isTargetOrNoTargets(PropertyTarget.AUTHORIZATION_REQUEST, opts.requestObject.targets)
  const isRequestByValue = opts.requestObject.passBy === PassBy.VALUE

  if (isRequestTarget && isRequestByValue && !requestObject) {
    throw Error(SIOPErrors.NO_JWT)
  }
  const request = isRequestByValue && requestObject ? await requestObject.toJwt() : undefined

  const authRequestPayload = {
    ...payload,
    //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
    ...(clientMetadata.client_id && { client_id: clientMetadata.client_id }),
    ...(isRequestTarget && opts.requestObject.passBy === PassBy.REFERENCE && { request_uri: opts.requestObject.reference_uri }),
    ...(isRequestTarget && isRequestByValue && { request }),
    ...(nonce && { nonce }),
    ...(state && { state }),
    ...(registration.payload &&
      registration.clientMetadataOpts.targets &&
      isTarget(PropertyTarget.AUTHORIZATION_REQUEST, registration.clientMetadataOpts.targets) && { ...registration.payload }),
    ...(claims && { claims }),
  }

  return removeNullUndefined(authRequestPayload)
}

export const assertValidRPRegistrationMedataPayload = (regObj: RPRegistrationMetadataPayload) => {
  if (regObj) {
    const valid = RPRegistrationMetadataPayloadSchema(regObj)
    if (!valid) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      //@ts-ignore
      throw new Error('Registration data validation error: ' + JSON.stringify(RPRegistrationMetadataPayloadSchema.errors))
    }
  }
  if (regObj?.subject_syntax_types_supported && regObj.subject_syntax_types_supported.length == 0) {
    throw new Error(`${SIOPErrors.VERIFY_BAD_PARAMS}`)
  }
}
