import { WrappedVerifiableCredential } from '@sphereon/ssi-types'

export type SupportedRevocationFormats = Exclude<WrappedVerifiableCredential['format'], 'vp+sd-jwt' | 'vc+sd-jwt'>
