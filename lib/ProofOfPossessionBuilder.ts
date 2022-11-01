import { createProofOfPossession } from './functions/ProofUtils';
import { PROOF_CANT_BE_CONSTRUCTED, ProofOfPossession, ProofOfPossessionOpts } from './types';

export class ProofOfPossessionBuilder {
  popCallbackOpts?: ProofOfPossessionOpts;
  popEncoded?: ProofOfPossession;

  withPoPCallbackOpts(popCallbackOpts: ProofOfPossessionOpts): ProofOfPossessionBuilder {
    this.popCallbackOpts = popCallbackOpts;
    return this;
  }

  withPoPEncoded(popEncoded: ProofOfPossession): ProofOfPossessionBuilder {
    this.popEncoded = popEncoded;
    return this;
  }

  public async build(): Promise<ProofOfPossession> {
    if (this.popEncoded) {
      return Promise.resolve(this.popEncoded);
    } else if (this.popCallbackOpts) {
      return await createProofOfPossession(this.popCallbackOpts);
    }
    throw new Error(PROOF_CANT_BE_CONSTRUCTED);
  }
}
