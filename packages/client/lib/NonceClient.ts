import { EndpointMetadata, formPost, IssuerOpts, OpenIDResponse } from '@sphereon/oid4vci-common'
import { MetadataClient } from './MetadataClient'

export interface NonceSuccessBodyV1_0_15 {
  c_nonce: string
}

export const sendNonceRequest = async (
  nonceEndpointUrl: string,
  opts?: { headers?: Record<string, string> }
): Promise<OpenIDResponse<NonceSuccessBodyV1_0_15>> => {
  // Empty x-www-form-urlencoded body (matches your formPost usage style)
  return await formPost<NonceSuccessBodyV1_0_15>(nonceEndpointUrl, new URLSearchParams(), {
    customHeaders: opts?.headers ? opts.headers : undefined
  })
}

export const acquireNonceFromAuthorizationServer = async (opts: {
  metadata?: EndpointMetadata
  issuerOpts?: IssuerOpts
  headers?: Record<string, string>
}): Promise<OpenIDResponse<NonceSuccessBodyV1_0_15>> => {
  const metadata = opts?.metadata
    ? opts.metadata
    : opts?.issuerOpts?.fetchMetadata
      ? await MetadataClient.retrieveAllMetadata(opts.issuerOpts.issuer, { errorOnNotFound: false })
      : undefined

  const nonceEndpointUrl = metadata?.nonce_endpoint
  if (!nonceEndpointUrl) {
    return Promise.reject(Error('Cannot determine nonce endpoint URL'))
  }

  return await sendNonceRequest(nonceEndpointUrl, { headers: opts?.headers })
}
