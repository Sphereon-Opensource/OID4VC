import { CredentialRequestClient } from './CredentialRequestClient';
import { createProofOfPossession } from './functions';
import { PROOF_CANT_BE_CONSTRUCTED, ProofOfPossession, ProofOfPossessionOpts } from './types';

export class ProofOfPossessionBuilder {
  proofCallbackOpts?: ProofOfPossessionOpts;
  proof?: ProofOfPossession;
  credentialRequestClient: CredentialRequestClient;

  withProofCallbackOpts(proofCallbackOpts: ProofOfPossessionOpts): ProofOfPossessionBuilder {
    this.proofCallbackOpts = proofCallbackOpts;
    return this;
  }

  withProof(proof: ProofOfPossession): ProofOfPossessionBuilder {
    this.proof = proof;
    return this;
  }

  withCredentialRequestClient(credentialRequestClient: CredentialRequestClient): ProofOfPossessionBuilder {
    this.credentialRequestClient = credentialRequestClient;
    return this;
  }

  public async build(): Promise<ProofOfPossession> {
    if (this.proof) {
      return Promise.resolve(this.proof);
    } else if (this.proofCallbackOpts) {
      return await createProofOfPossession(this.proofCallbackOpts, this.credentialRequestClient);
    }
    throw new Error(PROOF_CANT_BE_CONSTRUCTED);
  }
}
