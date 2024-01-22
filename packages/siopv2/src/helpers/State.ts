import { BAD_PARAMS } from '@sphereon/oid4vc-common';
import SHA from 'sha.js';
import { v4 as uuidv4 } from 'uuid';

import { base64urlEncodeBuffer } from './Encodings';

export function getNonce(state?: string, nonce?: string) {
  if (!nonce && !state) {
    throw Error(BAD_PARAMS + ': nonce or state required');
  }

  return nonce ?? toNonce(state);
}

export function toNonce(input?: string): string {
  const buff = SHA('sha256')
    .update(input ?? uuidv4())
    .digest();
  return base64urlEncodeBuffer(buff);
}

export function getState(state?: string) {
  return state || createState();
}

export function createState(): string {
  return uuidv4();
}
