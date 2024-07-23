import { DIDDocument as DIFDIDDocument } from 'did-resolver'

export interface LinkedDataProof {
  type: string
  created: string
  creator: string
  nonce: string
  signatureValue: string
}

export interface DIDDocument extends DIFDIDDocument {
  owner?: string
  created?: string
  updated?: string
  proof?: LinkedDataProof
}
