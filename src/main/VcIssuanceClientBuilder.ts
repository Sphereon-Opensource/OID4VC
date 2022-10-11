import { ClaimFormat } from '@sphereon/ssi-types';

import { VcIssuanceClient } from './VcIssuanceClient';
import { ProofOfPossession } from './types';

export default class VcIssuanceClientBuilder {
  credentialRequestUrl: string;
  credentialType: string | string[];
  format: ClaimFormat | ClaimFormat[];
  proof: ProofOfPossession;

  withCredentialRequestUrl(credentialRequestUrl: string): VcIssuanceClientBuilder {
    this.credentialRequestUrl = credentialRequestUrl;
    return this;
  }

  withCredentialType(credentialType: string | string[]): VcIssuanceClientBuilder {
    this.credentialType = credentialType;
    return this;
  }

  withFormat(format: ClaimFormat | ClaimFormat[]): VcIssuanceClientBuilder {
    this.format = format;
    return this;
  }

  withPoP(pop: ProofOfPossession): VcIssuanceClientBuilder {
    this.proof = pop;
    return this;
  }

  build(): VcIssuanceClient {
    return new VcIssuanceClient({ builder: this });
  }
}
