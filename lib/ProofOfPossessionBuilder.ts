import { createProofOfPossession } from './functions';
import { PROOF_CANT_BE_CONSTRUCTED, ProofOfPossession, ProofOfPossessionOpts } from './types';

export class ProofOfPossessionBuilder {
  popCallbackOpts?: ProofOfPossessionOpts;
  proof?: ProofOfPossession;

  withProofCallbackOpts(proofCallbackOpts: ProofOfPossessionOpts): ProofOfPossessionBuilder {
    this.popCallbackOpts = popCallbackOpts;
    return this;
  }

  withProof(proof: ProofOfPossession): ProofOfPossessionBuilder {
    this.proof = proof;
    return this;
  }

  public async build(): Promise<ProofOfPossession> {
    if (this.proof) {
      return Promise.resolve(this.proof);
    } else if (this.popCallbackOpts) {
      return await createProofOfPossession(this.popCallbackOpts);
    }
    throw new Error(PROOF_CANT_BE_CONSTRUCTED);
  }
}
