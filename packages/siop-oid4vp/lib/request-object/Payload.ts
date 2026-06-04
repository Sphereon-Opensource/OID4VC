import { uuidv4 } from '@sphereon/oid4vc-common'
import { CreateAuthorizationRequestOpts, createClaimsProperties } from '../authorization-request'
import { createRequestRegistration } from '../authorization-request/RequestRegistration'
import { getNonce, getState, removeNullUndefined } from '../helpers'
import { assertValidRequestObjectOpts } from './Opts'
import { RequestObjectPayload, ResponseMode, ResponseType, SIOPErrors, SupportedVersion } from '../types'

export const createRequestObjectPayload = async (opts: CreateAuthorizationRequestOpts): Promise<RequestObjectPayload | undefined> => {
  assertValidRequestObjectOpts(opts.requestObject, false)
  const payload = opts.requestObject.payload
  if (!payload) {
    return undefined // No request object apparently
  }
  assertValidRequestObjectOpts(opts.requestObject, true)

  /*if (!opts.clientMetadata) {
    return Promise.reject(Error('No client metadata found'))
  } else if (!payload.claims) {
    return Promise.reject(Error('No payload claims'))
  }*/
  const state = getState(payload.state)
  const registration = await createRequestRegistration(opts.clientMetadata, opts)
  const claims = await createClaimsProperties(payload.claims)

  const metadataKey = 'client_metadata'
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  const clientId = payload.client_id ?? registration.payload[metadataKey]?.client_id

  const now = Math.round(new Date().getTime() / 1000)
  const validInSec = 120 // todo config/option
  const iat = payload.iat ?? now
  const nbf = payload.nbf ?? iat
  const exp = payload.exp ?? iat + validInSec
  const aud = payload.aud
  const jti = payload.jti ?? uuidv4()

  const version = opts.version

  return removeNullUndefined({
    response_type: payload.response_type ?? ResponseType.ID_TOKEN,
    scope: payload.scope,
    //TODO implement /.well-known/openid-federation support in the OP side to resolve the client_id (URL) and retrieve the metadata
    ...(clientId && { client_id: clientId }),
    ...(payload.entity_id && { entity_id: payload.entity_id }),
    ...(payload.redirect_uri && { redirect_uri: payload.redirect_uri }),
    ...(payload.response_uri && { response_uri: payload.response_uri }),
    response_mode: payload.response_mode ?? ResponseMode.DIRECT_POST,
    ...(payload.id_token_hint && { id_token_hint: payload.id_token_hint }),
    registration_uri: registration.clientMetadataOpts.reference_uri,
    nonce: getNonce(state, payload.nonce),
    state,
    ...registration.payload,
    claims,
    ...(payload.dcql_query && { dcql_query: payload.dcql_query }),
    client_metadata: payload.client_metadata,
    iat,
    nbf,
    exp,
    jti,
    aud,
    // Version-specific fields
    ...(opts.transaction_data && { transaction_data: opts.transaction_data }),
    ...(version === SupportedVersion.OID4VP_v1 && {
      ...(opts.verifier_info && { verifier_info: opts.verifier_info }),
      ...(opts.request_uri_method && { request_uri_method: opts.request_uri_method }),
      ...(opts.expected_origins && { expected_origins: opts.expected_origins }),
      ...(opts.wallet_nonce && { wallet_nonce: opts.wallet_nonce }),
    }),
    ...(version === SupportedVersion.SIOPv2_OID4VP_D28 && {
      ...(opts.verifier_attestations && { verifier_attestations: opts.verifier_attestations }),
    }),
  })
}

export const assertValidRequestObjectPayload = (verPayload: RequestObjectPayload | undefined): void => {
  if (!verPayload) {
    throw Error("Request object payload can't be undefined")
  }
  if (verPayload['registration_uri'] && verPayload['registration']) {
    throw new Error(`${SIOPErrors.REG_OBJ_N_REG_URI_CANT_BE_SET_SIMULTANEOUSLY}`)
  }
}
