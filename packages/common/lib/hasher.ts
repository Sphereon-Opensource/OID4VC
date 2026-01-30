import { HasherSync, shaHasher } from '@sphereon/ssi-types'

export const defaultHasher: HasherSync = (data: string | ArrayBuffer | SharedArrayBuffer, algorithm: string) => {
  return shaHasher(data, algorithm)
}
