import { createProofOfPossession } from './functions';
import { EndpointMetadata, JwtArgs, PROOF_CANT_BE_CONSTRUCTED, ProofOfPossession, ProofOfPossessionArgs } from './types';

export class ProofOfPossessionBuilder {
  static proof?: ProofOfPossession;
  static proofCallbackArgs?: ProofOfPossessionArgs;

  endpointMetadata: EndpointMetadata;
  kid: string;
  clientId?: string;
  popJwtArgs?: JwtArgs;

  static fromProofCallbackArgs(proofCallbackArgs: ProofOfPossessionArgs): ProofOfPossessionBuilder {
    this.proofCallbackArgs = proofCallbackArgs;
    return new ProofOfPossessionBuilder();
  }

  static fromProof(proof: ProofOfPossession): ProofOfPossessionBuilder {
    this.proof = proof;
    return new ProofOfPossessionBuilder();
  }

  withEndpointMetadata(endpointMetadata: EndpointMetadata): ProofOfPossessionBuilder {
    this.endpointMetadata = endpointMetadata;
    return this;
  }

  withClientId(clientId: string): ProofOfPossessionBuilder {
    this.clientId = clientId;
    return this;
  }

  withKid(kid: string): ProofOfPossessionBuilder {
    this.kid = kid;
    return this;
  }

  withJwtArgs(popJwtArgs: JwtArgs): ProofOfPossessionBuilder {
    this.popJwtArgs = popJwtArgs;
    return this;
  }
  public async build(): Promise<ProofOfPossession> {
    if (ProofOfPossessionBuilder.proof) {
      return Promise.resolve(ProofOfPossessionBuilder.proof);
    } else if (ProofOfPossessionBuilder.proofCallbackArgs) {
      if (!this.kid) {
        throw new Error('No kid provided');
      }
      if (!this.endpointMetadata) {
        throw new Error('No endpointMetadata provided');
      }
      return await createProofOfPossession(
        ProofOfPossessionBuilder.proofCallbackArgs,
        this.kid,
        this.endpointMetadata,
        this.popJwtArgs,
        this.clientId
      );
    }
    throw new Error(PROOF_CANT_BE_CONSTRUCTED);
  }
}
