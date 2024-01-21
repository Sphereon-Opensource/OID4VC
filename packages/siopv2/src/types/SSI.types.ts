import { JWTVerifyOptions } from 'did-jwt';
import { DIDDocument as DIFDIDDocument, Resolvable } from 'did-resolver';

export interface ResolveOpts {
  jwtVerifyOpts?: JWTVerifyOptions;
  resolver?: Resolvable;
  resolveUrl?: string;

  // By default we fallback to the universal resolver for max interop.
  noUniversalResolverFallback?: boolean;
  subjectSyntaxTypesSupported?: string[];
}

/*export interface PublicKey {
    id: string;
    type: string;
    controller: string;
    ethereumAddress?: string;
    publicKeyBase64?: string;
    publicKeyBase58?: string;
    publicKeyHex?: string;
    publicKeyPem?: string;
    publicKeyJwk?: JWK;
}*/
/*export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyHex?: string;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
  publicKeyJwk?: JWK;
}*/
/*
export interface Authentication {
    type: string;
    publicKey: string;
}*/
export interface LinkedDataProof {
  type: string;
  created: string;
  creator: string;
  nonce: string;
  signatureValue: string;
}
/*
export interface ServiceEndpoint {
    id: string;
    type: string;
    serviceEndpoint: string;
    description?: string;
}
*/
export interface DIDDocument extends DIFDIDDocument {
  owner?: string;
  created?: string;
  updated?: string;
  proof?: LinkedDataProof;
}
