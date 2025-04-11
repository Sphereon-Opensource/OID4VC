import { InputDescriptorV1 } from '@sphereon/pex-models'
import { parse, stringify } from 'qs'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as ua8 from 'uint8arrays'

import { SIOPErrors } from '../types'

export function decodeUriAsJson(uri: string) {
  if (!uri) {
    throw new Error(SIOPErrors.BAD_PARAMS)
  }
  const queryString = uri.replace(/^([a-zA-Z][a-zA-Z0-9-_]*:\/\/.*[?])/, '')
  if (!queryString) {
    throw new Error(SIOPErrors.BAD_PARAMS)
  }
  const parts = parse(queryString, { plainObjects: true, depth: 10, parameterLimit: 5000, ignoreQueryPrefix: true })

  const vpToken = (parts?.claims as { [key: string]: any })?.['vp_token']
  const descriptors = vpToken?.presentation_definition?.['input_descriptors'] // FIXME?
  if (descriptors && Array.isArray(descriptors)) {
    // Whenever we have a [{'uri': 'str1'}, 'uri': 'str2'] qs changes this to {uri: ['str1','str2']} which means schema validation fails. So we have to fix that
    vpToken.presentation_definition['input_descriptors'] = descriptors.map((descriptor: InputDescriptorV1) => {
      if (Array.isArray(descriptor.schema)) {
        descriptor.schema = descriptor.schema.flatMap((val) => {
          if (typeof val === 'string') {
            return { uri: val }
          } else if (typeof val === 'object' && Array.isArray(val.uri)) {
            return val.uri.map((uri) => ({ uri: uri as string }))
          }
          return val
        })
      }
      return descriptor
    })
  }

  const json: Record<string, any> = {}
  for (const key in parts) {
    const value = parts[key]
    if (!value) {
      continue
    }
    const isBool = typeof value == 'boolean'
    const isNumber = typeof value == 'number'
    const isString = typeof value == 'string'

    if (isBool || isNumber) {
      json[decodeURIComponent(key)] = value
    } else if (isString) {
      const decoded = decodeURIComponent(value)
      if (decoded.startsWith('{') && decoded.endsWith('}')) {
        json[decodeURIComponent(key)] = JSON.parse(decoded)
      } else {
        json[decodeURIComponent(key)] = decoded
      }
    }
  }
  return JSON.parse(JSON.stringify(json))
}

export function encodeJsonAsURI(json: Record<string, unknown>, _opts?: { arraysWithIndex?: string[] }): string {
  if (typeof json === 'string') {
    return encodeJsonAsURI(JSON.parse(json))
  }

  const results: string[] = []

  function encodeAndStripWhitespace(key: string): string {
    return encodeURIComponent(key.replace(' ', ''))
  }

  for (const [key, value] of Object.entries(json)) {
    if (!value) {
      continue
    }
    const isBool = typeof value == 'boolean'
    const isNumber = typeof value == 'number'
    const isString = typeof value == 'string'
    const isArray = Array.isArray(value)
    let encoded: string
    if (isBool || isNumber) {
      encoded = `${encodeAndStripWhitespace(key)}=${value}`
    } else if (isString) {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeURIComponent(value)}`
    } else if (isArray && _opts?.arraysWithIndex?.includes(key)) {
      encoded = `${encodeAndStripWhitespace(key)}=${stringify(value, { arrayFormat: 'brackets' })}`
    } else {
      encoded = `${encodeAndStripWhitespace(key)}=${encodeURIComponent(JSON.stringify(value))}`
    }
    results.push(encoded)
  }
  return results.join('&')
}

export function base64ToHexString(input: string, encoding?: 'base64url' | 'base64'): string {
  return ua8.toString(ua8.fromString(input, encoding ?? 'base64url'), 'base16')
}

export function fromBase64(base64: string): string {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

export function base64urlEncodeBuffer(buf: { toString: (arg0: 'base64') => string }): string {
  return fromBase64(buf.toString('base64'))
}

export function base64urlToString(base64url: string): string {
  const uint8array = ua8.fromString(base64url, 'base64url')
  return ua8.toString(uint8array, 'ascii')
}
