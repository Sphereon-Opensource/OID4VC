import { ExternalSignature, InternalSignature, NoSignature, SuppliedSignature } from './types/SIOP.types'

export const isInternalSignature = (object: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature): object is InternalSignature =>
  'hexPrivateKey' in object && 'did' in object

export const isExternalSignature = (object: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature): object is ExternalSignature =>
  'signatureUri' in object && 'did' in object

export const isSuppliedSignature = (object: InternalSignature | ExternalSignature | SuppliedSignature | NoSignature): object is SuppliedSignature =>
  'signature' in object
