import { fetch } from 'cross-fetch'
import pkg from 'debug'
const { debug: Debug } = pkg

import { ContentType, SIOPErrors, SIOPResonse } from '../types'

const debug = Debug('sphereon:siopv2:http')

export const getJson = async <T>(
  URL: string,
  opts?: {
    bearerToken?: string
    contentType?: string | ContentType
    accept?: string
    customHeaders?: HeadersInit
    exceptionOnHttpErrorStatus?: boolean
  },
): Promise<SIOPResonse<T>> => {
  return await siopFetch(URL, undefined, { method: 'GET', ...opts })
}

export const formPost = async <T>(
  url: string,
  body: BodyInit,
  opts?: {
    bearerToken?: string
    contentType?: string | ContentType
    accept?: string
    customHeaders?: HeadersInit
    exceptionOnHttpErrorStatus?: boolean
  },
): Promise<SIOPResonse<T>> => {
  return await post(url, body, opts?.contentType ? { ...opts } : { contentType: ContentType.FORM_URL_ENCODED, ...opts })
}

export const post = async <T>(
  url: string,
  body?: BodyInit,
  opts?: {
    bearerToken?: string
    contentType?: string | ContentType
    accept?: string
    customHeaders?: HeadersInit
    exceptionOnHttpErrorStatus?: boolean
  },
): Promise<SIOPResonse<T>> => {
  return await siopFetch(url, body, { method: 'POST', ...opts })
}

const siopFetch = async <T>(
  url: string,
  body?: BodyInit,
  opts?: {
    method?: string
    bearerToken?: string
    contentType?: string | ContentType
    accept?: string
    customHeaders?: HeadersInit
    exceptionOnHttpErrorStatus?: boolean
  },
): Promise<SIOPResonse<T>> => {
  if (!url || url.toLowerCase().startsWith('did:')) {
    throw Error(`Invalid URL supplied. Expected a http(s) URL. Recieved: ${url}`)
  }
  const headers: Record<string, any> = opts?.customHeaders ? opts.customHeaders : {}
  if (opts?.bearerToken) {
    headers['Authorization'] = `Bearer ${opts.bearerToken}`
  }
  const method = opts?.method ? opts.method : body ? 'POST' : 'GET'
  const accept = opts?.accept ? opts.accept : 'application/json'
  headers['Content-Type'] = opts?.contentType ? opts.contentType : method !== 'GET' ? 'application/json' : undefined
  headers['Accept'] = accept

  const payload: RequestInit = {
    method,
    headers,
    body,
  }

  debug(`START fetching url: ${url}`)
  if (body) {
    debug(`Body:\r\n${JSON.stringify(body)}`)
  }
  debug(`Headers:\r\n${JSON.stringify(payload.headers)}`)
  const origResponse = await fetch(url, payload)
  const clonedResponse = origResponse.clone()
  const success = origResponse && origResponse.status >= 200 && origResponse.status < 400
  const textResponseBody = await clonedResponse.text()

  const isJSONResponse =
    (accept === 'application/json' || origResponse.headers.get('Content-Type') === 'application/json') && textResponseBody.trim().startsWith('{')
  const responseBody = isJSONResponse ? JSON.parse(textResponseBody) : textResponseBody

  if (success || opts?.exceptionOnHttpErrorStatus) {
    debug(`${success ? 'success' : 'error'} status: ${clonedResponse.status}, body:\r\n${JSON.stringify(responseBody)}`)
  } else {
    console.warn(`${success ? 'success' : 'error'} status: ${clonedResponse.status}, body:\r\n${JSON.stringify(responseBody)}`)
  }

  if (!success && opts?.exceptionOnHttpErrorStatus) {
    const error = JSON.stringify(responseBody)
    throw new Error(error === '{}' ? '{"error": "not found"}' : error)
  }
  debug(`END fetching url: ${url}`)

  return {
    origResponse,
    successBody: success ? responseBody : undefined,
    errorBody: !success ? responseBody : undefined,
  }
}

export const getWithUrl = async <T>(url: string, textResponse?: boolean): Promise<T> => {
  // try {
  const response = await fetch(url)
  if (response.status >= 400) {
    return Promise.reject(Error(`${SIOPErrors.RESPONSE_STATUS_UNEXPECTED} ${response.status}:${response.statusText} URL: ${url}`))
  }
  if (textResponse === true) {
    return (await response.text()) as unknown as T
  }
  return await response.json()
  /*} catch (e) {
    return Promise.reject(Error(`${(e as Error).message}`));
  }*/
}

export const fetchByReferenceOrUseByValue = async <T>(referenceURI: string, valueObject: T, textResponse?: boolean): Promise<T> => {
  let response: T = valueObject
  if (referenceURI) {
    try {
      response = await getWithUrl(referenceURI, textResponse)
    } catch (e) {
      console.log(e)
      throw new Error(`${SIOPErrors.REG_PASS_BY_REFERENCE_INCORRECTLY}: ${(e as Error).message}, URL: ${referenceURI}`)
    }
  }
  return response
}
