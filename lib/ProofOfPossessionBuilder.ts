import { ProofOfPossession, ProofOfPossessionCallback, ProofOfPossessionCallbackArgs } from './types';

export class ProofOfPossessionBuilder {
  proofOfPossession?: ProofOfPossession;
  proofOfPossessionCallbackFunction?: ProofOfPossessionCallback;
  proofOfPossessionCallbackArgs?: ProofOfPossessionCallbackArgs;

  withProofOfPossession(proofOfPossession: ProofOfPossession): ProofOfPossessionBuilder {
    this.proofOfPossession = proofOfPossession;
    return this;
  }

  withProofOfPossessionCallback(
    proofOfPossessionCallbackFunction: ProofOfPossessionCallback,
    proofOfPossessionCallbackArgs: ProofOfPossessionCallbackArgs
  ): ProofOfPossessionBuilder {
    this.proofOfPossessionCallbackFunction = proofOfPossessionCallbackFunction;
    this.proofOfPossessionCallbackArgs = proofOfPossessionCallbackArgs;
    return this;
  }

  public async build(): Promise<ProofOfPossession> {
    return this.proofOfPossession ? this.proofOfPossession : await this.proofOfPossessionCallbackFunction(this.proofOfPossessionCallbackArgs);
  }
}
