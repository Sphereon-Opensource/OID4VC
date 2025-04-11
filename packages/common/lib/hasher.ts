import { HasherSync } from '@sphereon/ssi-types';
import sha from 'sha.js';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import * as u8a from 'uint8arrays';

const supportedAlgorithms = ['sha256', 'sha384', 'sha512'] as const;
type SupportedAlgorithms = (typeof supportedAlgorithms)[number];

export const defaultHasher: HasherSync = (data, algorithm) => {
  const sanitizedAlgorithm = algorithm.toLowerCase().replace(/[-_]/g, '');
  if (!supportedAlgorithms.includes(sanitizedAlgorithm as SupportedAlgorithms)) {
    throw new Error(`Unsupported hashing algorithm ${algorithm}`);
  }

  return new Uint8Array(
    sha(sanitizedAlgorithm as SupportedAlgorithms)
      .update(typeof data === 'string' ? u8a.fromString(data) : data)
      .digest(),
  );
};
