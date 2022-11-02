import { createProofOfPossession } from './functions';
import { EndpointMetadata, PROOF_CANT_BE_CONSTRUCTED, ProofOfPossession, ProofOfPossessionOpts } from './types';

export class ProofOfPossessionBuilder {
  proofCallbackOpts?: ProofOfPossessionOpts;
  proof?: ProofOfPossession;
  endpointMetadata: EndpointMetadata;

  withProofCallbackOpts(proofCallbackOpts: ProofOfPossessionOpts): ProofOfPossessionBuilder {
    this.proofCallbackOpts = proofCallbackOpts;
    return this;
  }

  withProof(proof: ProofOfPossession): ProofOfPossessionBuilder {
    this.proof = proof;
    return this;
  }

  withEndpointMetadata(endpointMetadata: EndpointMetadata): ProofOfPossessionBuilder {
    this.endpointMetadata = endpointMetadata;
    return this;
  }

  public async build(): Promise<ProofOfPossession> {
    if (this.proof) {
      return Promise.resolve(this.proof);
    } else if (this.proofCallbackOpts) {
      return await createProofOfPossession(this.proofCallbackOpts, this.endpointMetadata);
    }
    throw new Error(PROOF_CANT_BE_CONSTRUCTED);
  }
}
