import { uuidv4 } from '@sphereon/oid4vc-common'
import SHA from 'sha.js'

import { base64urlEncodeBuffer } from './Encodings'

export function getNonce(state: string, nonce?: string) {
  return nonce || toNonce(state)
}

export function toNonce(input: string): string {
  const buff = SHA('sha256').update(input).digest()
  return base64urlEncodeBuffer(buff)
}

export function getState(state?: string) {
  return state || createState()
}

export function createState(): string {
  return uuidv4()
}
