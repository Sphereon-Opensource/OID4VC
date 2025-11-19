// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as u8a from 'uint8arrays'

const { fromString, toString } = u8a

export function base64ToHexString(input: string, encoding?: 'base64url' | 'base64'): string {
  return toString(fromString(input, encoding ?? 'base64url'), 'base16')
}

export function fromBase64(base64: string): string {
  return base64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

export function base64urlEncodeBuffer(buf: { toString: (arg0: 'base64') => string }): string {
  return fromBase64(buf.toString('base64'))
}

export function base64urlToString(base64url: string): string {
  const uint8array = fromString(base64url, 'base64url')
  return toString(uint8array, 'ascii')
}
