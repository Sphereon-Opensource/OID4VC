import { SigningAlgo } from '@sphereon/oid4vc-common'
import { VerifyCallback as WellknownDIDVerifyCallback } from '@sphereon/wellknown-dids-client'
import { JWTVerifyOptions } from 'did-jwt'
import { Resolvable } from 'did-resolver'

export enum CheckLinkedDomain {
  NEVER = 'never', // We don't want to verify Linked domains
  IF_PRESENT = 'if_present', // If present, did-auth-siop will check the linked domain, if exist and not valid, throws an exception
  ALWAYS = 'always', // We'll always check the linked domains, if not exist or not valid, throws an exception
}

export interface InternalSignature {
  hexPrivateKey: string // hex private key Only secp256k1 format
  did: string

  alg: SigningAlgo
  kid?: string // Optional: key identifier

  customJwtSigner?: Signer
}

export interface SuppliedSignature {
  signature: (data: string | Uint8Array) => Promise<EcdsaSignature | string>

  alg: SigningAlgo
  did: string
  kid: string
}

export interface NoSignature {
  hexPublicKey: string // hex public key
  did: string
  kid?: string // Optional: key identifier
}

export interface ExternalSignature {
  signatureUri: string // url to call to generate a withSignature
  did: string
  authZToken: string // Optional: bearer token to use to the call
  hexPublicKey?: string // Optional: hex encoded public key to compute JWK key, if not possible from DIDres Document

  alg: SigningAlgo
  kid?: string // Optional: key identifier. default did#keys-1
}

export enum VerificationMode {
  INTERNAL,
  EXTERNAL,
}

export interface EcdsaSignature {
  r: string
  s: string
  recoveryParam?: number | null
}
export type Signer = (data: string | Uint8Array) => Promise<EcdsaSignature | string>

export interface Verification {
  checkLinkedDomain?: CheckLinkedDomain
  wellknownDIDVerifyCallback?: WellknownDIDVerifyCallback
  resolveOpts: ResolveOpts
}

export type InternalVerification = Verification

export interface ExternalVerification extends Verification {
  verifyUri: string // url to call to verify the id_token withSignature
  authZToken?: string // Optional: bearer token to use to the call
}

export interface ResolveOpts {
  jwtVerifyOpts?: JWTVerifyOptions
  resolver?: Resolvable
  resolveUrl?: string
  noUniversalResolverFallback?: boolean
  subjectSyntaxTypesSupported?: string[]
}
