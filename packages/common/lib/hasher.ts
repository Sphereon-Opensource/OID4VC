import { Hasher } from '@sphereon/ssi-types';
import sha from 'sha.js';

const supportedAlgorithms = ['sha256', 'sha384', 'sha512'] as const;
type SupportedAlgorithms = (typeof supportedAlgorithms)[number];

export const defaultHasher: Hasher = (data, algorithm) => {
  if (!supportedAlgorithms.includes(algorithm as SupportedAlgorithms)) {
    throw new Error(`Unsupported hashing algorithm ${algorithm}`);
  }

  return new Uint8Array(
    sha(algorithm as SupportedAlgorithms)
      .update(data)
      .digest(),
  );
};
