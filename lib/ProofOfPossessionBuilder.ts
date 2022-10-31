import { createProofOfPossession, encodeProof } from './functions/ProofUtils';
import { PoPSignInputDecoded, PROOF_CANT_BE_CONSTRUCTED, ProofOfPossession, ProofOfPossessionOpts, ProofType } from './types';

export class ProofOfPossessionBuilder {
  popCallbackOpts?: ProofOfPossessionOpts;
  popSignInputDecodedArgs?: PoPSignInputDecoded;
  popEncoded?: ProofOfPossession;

  withPoPSignInputDecodedArgs(popSignInputDecodedArgs: PoPSignInputDecoded): ProofOfPossessionBuilder {
    this.popSignInputDecodedArgs = popSignInputDecodedArgs;
    return this;
  }

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
    } else if (this.popSignInputDecodedArgs) {
      return {
        jwt: await encodeProof(this.popSignInputDecodedArgs),
        proof_type: ProofType.JWT,
      };
    } else if (this.popCallbackOpts) {
      return await createProofOfPossession(this.popCallbackOpts);
    }
    throw new Error(PROOF_CANT_BE_CONSTRUCTED);
  }
}
