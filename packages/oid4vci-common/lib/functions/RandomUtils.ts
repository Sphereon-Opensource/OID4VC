import { defaultHasher } from '@sphereon/oid4vc-common'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as u8a from 'uint8arrays'
const { toString } = u8a
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { SupportedEncodings } from 'uint8arrays/to-string'

import { CodeChallengeMethod } from '../types'

import randomBytes from './randomBytes.cjs'

export const CODE_VERIFIER_DEFAULT_LENGTH = 128
export const NONCE_LENGTH = 32

export const generateRandomString = (length: number, encoding?: SupportedEncodings): string => {
  return toString(randomBytes(length), encoding).slice(0, length)
}

export const generateNonce = (length?: number): string => {
  return generateRandomString(length ?? NONCE_LENGTH)
}
export const generateCodeVerifier = (length?: number): string => {
  const codeVerifier = generateRandomString(length ?? CODE_VERIFIER_DEFAULT_LENGTH, 'base64url')
  assertValidCodeVerifier(codeVerifier)
  return codeVerifier
}

export const createCodeChallenge = (codeVerifier: string, codeChallengeMethod?: CodeChallengeMethod): string => {
  if (codeChallengeMethod === CodeChallengeMethod.plain) {
    return codeVerifier
  } else if (!codeChallengeMethod || codeChallengeMethod === CodeChallengeMethod.S256) {
    return toString(defaultHasher(codeVerifier, 'sha256'), 'base64url')
  } else {
    // Just a precaution if a new method would be introduced
    throw Error(`code challenge method ${codeChallengeMethod} not implemented`)
  }
}

export const assertValidCodeVerifier = (codeVerifier: string) => {
  const length = codeVerifier.length
  if (length < 43) {
    throw Error(`code_verifier should have a minimum length of 43; see rfc7636`)
  } else if (length > 128) {
    throw Error(`code_verifier should have a maximum length of 128; see rfc7636`)
  }
}
